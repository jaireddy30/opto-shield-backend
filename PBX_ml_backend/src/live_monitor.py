"""
PBX SHIELD — Real Production Monitor
=====================================
Watches ACTUAL SIP traffic on your Asterisk box and classifies it with your
trained LightGBM model every 60 seconds. Optionally blocks attacking IPs
with iptables.

WHERE THE DATA COMES FROM (two real sources, combined):
  1. Asterisk's own SIP log (`pjsip set logger on`) — this sees every raw
     SIP request/response that hits port 5060, including scans and
     brute-force attempts that never complete a call. This is where
     OPTIONS floods, SIP scanners, register brute force, and extension
     enumeration get detected.
  2. Asterisk Manager Interface (AMI) `Cdr` events — real completed call
     records with accurate duration, used to enrich INVITE events and
     catch toll fraud (long calls to unusual destinations).

REQUIRED ASTERISK-SIDE SETUP (do this first):
  1. Enable the PJSIP logger so raw SIP traffic gets written to the log:
       asterisk -rx "pjsip set logger on"
     To make it persist across restarts, add to /etc/asterisk/pjsip.conf:
       [logger]
       type=logger
       enabled=yes
  2. Make sure /etc/asterisk/manager.conf has an AMI user that can read
     "cdr" and "call" events, e.g.:
       [pbxshield]
       secret = CHANGE_ME
       read = system,call,cdr
       write =
       permit = 127.0.0.1/255.255.255.255
  3. Update AMI_USER / AMI_PASS below to match.
  4. Update ASTERISK_LOG_PATH below if your log isn't at the default path
     (check with: asterisk -rx "core show settings" | grep -i log).

SAFETY — READ THIS BEFORE ENABLING BLOCKING:
  - TRUNK_WHITELIST below MUST contain your SIP trunk provider's IP(s).
    If you block your own trunk provider, real calls stop working until
    someone notices and manually removes the iptables rule.
  - DRY_RUN defaults to True. In dry-run, the script tells you exactly
    what it *would* have blocked, but doesn't touch iptables. Watch it
    classify real traffic correctly for a while before flipping this off.
"""

import os
import re
import sys
import time
import socket
import joblib
import threading
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from feature_engineering import compute_window_features

# ---------------------------------------------------------------------------
# CONFIGURATION — edit this section for your server
# ---------------------------------------------------------------------------

ASTERISK_LOG_PATH = "/var/log/asterisk/full"

AMI_HOST = "127.0.0.1"
AMI_PORT = 5038
AMI_USER = "pbxshield"
AMI_PASS = "CHANGE_ME"

# IPs that must NEVER be blocked, no matter what the model says.
# Put your SIP trunk provider IP(s) and any internal ranges here.
TRUNK_WHITELIST = {
    # "203.0.113.10",   # <-- example: your VoIP trunk provider
}

DRY_RUN = True                  # True = log what would be blocked, don't block
BAN_DURATION_MINUTES = 10
WINDOW_SECONDS = 60

MODEL_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "models", "lightgbm_pbx_model.pkl")
LOG_FILE = os.path.join(SCRIPT_DIR, "live_blocks.log")

# ---------------------------------------------------------------------------
# Load model
# ---------------------------------------------------------------------------
print("=" * 70)
print("  PBX SHIELD — LIVE MONITOR (real traffic)")
print("=" * 70)
try:
    model_data = joblib.load(MODEL_PATH)
    model = model_data["model"]
    FEATURES = model_data["features"]
    LABELS = model_data["labels"]
    print(f"  [+] Model loaded: {MODEL_PATH}")
except Exception as e:
    print(f"  [!] Failed to load model: {e}")
    sys.exit(1)

if DRY_RUN:
    print("  [i] DRY RUN is ON — no firewall rules will actually be applied.")
if not TRUNK_WHITELIST:
    print("  [!] WARNING: TRUNK_WHITELIST is empty. If you enable real blocking,")
    print("      your own SIP trunk provider could get blocked. Fill this in.")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
window_events = []
window_lock = threading.Lock()
BLOCKED_IPS = {}

# recent completed call durations keyed by source IP, used to enrich INVITE
# events picked up from the log with real duration from AMI Cdr records.
recent_durations = defaultdict(list)
durations_lock = threading.Lock()

KNOWN_EXTENSIONS_CACHE = None  # filled from Asterisk if desired; optional


def add_event(event):
    with window_lock:
        window_events.append(event)


# ---------------------------------------------------------------------------
# SOURCE 1 — tail Asterisk's SIP log (raw request/response traffic)
# ---------------------------------------------------------------------------
# Matches the request/response block headers produced by `pjsip set logger on`
REQ_HEADER_RE = re.compile(r"Received SIP request .* from UDP:([\d.]+):(\d+)")
RES_HEADER_RE = re.compile(r"Transmitting SIP response .* to UDP:([\d.]+):(\d+)")
REQUEST_LINE_RE = re.compile(r"^(INVITE|REGISTER|OPTIONS|ACK|BYE|CANCEL)\s+sip:([^@\s]+)@")
STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})")
CALLID_RE = re.compile(r"^Call-ID:\s*(.+)$", re.IGNORECASE)
FROM_RE = re.compile(r"^From:.*sip:([^@;\s]+)@", re.IGNORECASE)


def classify_response(code):
    return code


def tail_asterisk_log():
    if not os.path.exists(ASTERISK_LOG_PATH):
        print(f"  [!] Asterisk log not found at {ASTERISK_LOG_PATH}")
        print("      Update ASTERISK_LOG_PATH and make sure `pjsip set logger on` is enabled.")
        return

    print(f"  [+] Tailing {ASTERISK_LOG_PATH} for live SIP traffic...")

    pending = {}   # call_id -> {method, source_ip, extension, caller}

    with open(ASTERISK_LOG_PATH, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)  # only new lines from now on

        mode = None          # "request" | "response" | None
        cur_ip = None
        cur_method = None
        cur_ext = None
        cur_caller = "Unknown"
        cur_status = None
        cur_callid = None

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            line = line.rstrip("\n")

            req_match = REQ_HEADER_RE.search(line)
            res_match = RES_HEADER_RE.search(line)

            if req_match:
                mode = "request"
                cur_ip = req_match.group(1)
                cur_method = cur_ext = cur_caller = cur_callid = None
                continue

            if res_match:
                mode = "response"
                cur_ip = res_match.group(1)
                cur_status = cur_callid = None
                continue

            if mode == "request":
                m = REQUEST_LINE_RE.match(line)
                if m:
                    cur_method = m.group(1)
                    cur_ext = m.group(2)
                f_match = FROM_RE.match(line)
                if f_match:
                    cur_caller = f_match.group(1)
                c_match = CALLID_RE.match(line)
                if c_match:
                    cur_callid = c_match.group(1).strip()
                    if cur_method in ("INVITE", "REGISTER", "OPTIONS"):
                        pending[cur_callid] = {
                            "method": cur_method,
                            "source_ip": cur_ip,
                            "extension": cur_ext or "Unknown",
                            "caller": cur_caller,
                            "ts": datetime.now(),
                        }

            elif mode == "response":
                s_match = STATUS_LINE_RE.match(line)
                if s_match:
                    cur_status = s_match.group(1)
                c_match = CALLID_RE.match(line)
                if c_match:
                    cur_callid = c_match.group(1).strip()
                    info = pending.pop(cur_callid, None)
                    if info and cur_status:
                        duration = 0.0
                        if info["method"] == "INVITE" and cur_status == "200":
                            with durations_lock:
                                recs = recent_durations.get(info["source_ip"], [])
                                if recs:
                                    duration = recs.pop(0)
                        add_event({
                            "sip_method": info["method"],
                            "caller_id": info["caller"],
                            "destination_extension": info["extension"],
                            "response": cur_status,
                            "source_ip": info["source_ip"],
                            "duration": duration,
                        })
                        cur_callid = None


# ---------------------------------------------------------------------------
# SOURCE 2 — AMI Cdr events (real call durations, for toll fraud + INVITE
# duration enrichment). Also directly logs completed calls into the window
# in case the log tailer missed the closing response (e.g. log rotation).
# ---------------------------------------------------------------------------
def ami_cdr_listener():
    print(f"  [+] Connecting to Asterisk AMI at {AMI_HOST}:{AMI_PORT}...")
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((AMI_HOST, AMI_PORT))
            s.settimeout(None)
            s.recv(4096)  # banner

            login = (f"Action: Login\r\nUsername: {AMI_USER}\r\n"
                      f"Secret: {AMI_PASS}\r\nEvents: call,cdr\r\n\r\n")
            s.sendall(login.encode())

            buf = ""
            while True:
                data = s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    break
                buf += data
                while "\r\n\r\n" in buf:
                    block, buf = buf.split("\r\n\r\n", 1)
                    fields = {}
                    for line in block.split("\r\n"):
                        if ": " in line:
                            k, v = line.split(": ", 1)
                            fields[k.strip()] = v.strip()

                    if fields.get("Event") == "Cdr":
                        src = fields.get("Source", "Unknown")
                        dst = fields.get("Destination", "Unknown")
                        billsec = float(fields.get("BillableSeconds", 0) or 0)
                        disposition = fields.get("Disposition", "")
                        channel = fields.get("Channel", "")

                        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", channel)
                        source_ip = ip_match.group(1) if ip_match else None

                        if source_ip and billsec > 0:
                            with durations_lock:
                                recent_durations[source_ip].append(billsec)

                        # If the disposition suggests toll-fraud-like usage
                        # (long call, external destination) feed it in directly
                        # as a safety net even if the log tailer missed it.
                        if disposition == "ANSWERED" and source_ip:
                            add_event({
                                "sip_method": "INVITE",
                                "caller_id": fields.get("CallerID", "Unknown"),
                                "destination_extension": dst,
                                "response": "200",
                                "source_ip": source_ip,
                                "duration": billsec,
                            })
        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"  [!] AMI connection issue ({e}). Retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"  [!] AMI listener error: {e}. Retrying in 10s...")
            time.sleep(10)


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
def execute_firewall_block(ip_address, reason, confidence):
    if ip_address in TRUNK_WHITELIST:
        print(f"  [SKIP] {ip_address} is whitelisted (trunk/internal) — not blocking.")
        return
    if ip_address.startswith("192.168.") or ip_address in ("127.0.0.1", "0.0.0.0", None):
        print(f"  [SKIP] Ignoring local/invalid IP: {ip_address}")
        return

    unban_time = datetime.now() + timedelta(minutes=BAN_DURATION_MINUTES)
    BLOCKED_IPS[ip_address] = {"reason": reason, "unban_time": unban_time}

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True) if os.path.dirname(LOG_FILE) else None
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {'[DRY RUN] ' if DRY_RUN else ''}"
                f"BLOCK {ip_address} | {reason} ({confidence:.1f}%) | {BAN_DURATION_MINUTES}m\n")

    if DRY_RUN:
        print(f"  [DRY RUN] Would block {ip_address} for {reason} ({confidence:.1f}% confidence)")
        return

    print(f"  [FIREWALL] Blocking {ip_address} for {reason}")
    os.system(f"sudo iptables -I INPUT -s {ip_address} -p udp --dport 5060 -j DROP")
    os.system(f"sudo iptables -I INPUT -s {ip_address} -p tcp --dport 5060 -j DROP")


def clean_expired_bans():
    now = datetime.now()
    expired = [ip for ip, d in BLOCKED_IPS.items() if d["unban_time"] <= now]
    for ip in expired:
        del BLOCKED_IPS[ip]
        if not DRY_RUN:
            os.system(f"sudo iptables -D INPUT -s {ip} -p udp --dport 5060 -j DROP")
            os.system(f"sudo iptables -D INPUT -s {ip} -p tcp --dport 5060 -j DROP")
        print(f"  [FIREWALL] {ip} unbanned (expired)")


# ---------------------------------------------------------------------------
# Classification loop
# ---------------------------------------------------------------------------
def analysis_loop():
    print(f"  [+] Analysis engine started — classifying every {WINDOW_SECONDS}s.\n")
    while True:
        time.sleep(WINDOW_SECONDS)
        clean_expired_bans()

        with window_lock:
            events = window_events[:]
            window_events.clear()

        if not events:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 0 real events this window. (Idle)")
            continue

        features = compute_window_features(events)
        feature_values = [[features[f] for f in FEATURES]]
        pred = model.predict(feature_values)[0]
        proba = model.predict_proba(feature_values)[0]
        confidence = float(max(proba)) * 100
        classification = LABELS.get(int(pred), "UNKNOWN")

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(events)} real events -> "
              f"{classification} ({confidence:.1f}%)")

        if classification != "NORMAL":
            ips = [e["source_ip"] for e in events if e.get("source_ip")]
            if ips:
                attacker_ip = Counter(ips).most_common(1)[0][0]
                if attacker_ip not in BLOCKED_IPS:
                    execute_firewall_block(attacker_ip, classification, confidence)


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    threading.Thread(target=tail_asterisk_log, daemon=True).start()
    threading.Thread(target=ami_cdr_listener, daemon=True).start()
    threading.Thread(target=analysis_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [PBX SHIELD] Shutting down.")
        sys.exit(0)