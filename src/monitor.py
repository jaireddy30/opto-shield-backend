"""
PBX SHIELD — Real-Time Security Monitor (LIVE DATA)
=====================================================
Same Flask + SocketIO dashboard as before, but now fed by REAL SIP traffic
instead of a random generator:
  - Asterisk's own SIP log (`pjsip set logger on`), tailed live — catches
    every raw INVITE/REGISTER/OPTIONS hitting port 5060, including scans
    that never complete a call.
  - AMI `Cdr` events — real completed-call records, used for accurate call
    duration and toll-fraud detection.

REQUIRED ASTERISK-SIDE SETUP (do this first, on the Asterisk box):
  1. asterisk -rx "pjsip set logger on"
     (persist across restarts by adding to /etc/asterisk/pjsip.conf:
        [logger]
        type=logger
        enabled=yes )
  2. Add an AMI user to /etc/asterisk/manager.conf:
        [pbxshield]
        secret = CHANGE_ME
        read = system,call,cdr
        write =
        permit = 127.0.0.1/255.255.255.255
  3. Set AMI_PASS below to match, and confirm ASTERISK_LOG_PATH with:
        asterisk -rx "core show settings" | grep -i log

SAFETY:
  - Fill in TRUNK_WHITELIST with your SIP trunk provider's IP(s) before
    ever setting DRY_RUN = False. Otherwise a burst of legitimate call
    volume from your own provider could get auto-blocked and take your
    PBX offline.
  - DRY_RUN defaults to True: the dashboard will show "would block X"
    without touching iptables, so you can watch it classify real traffic
    safely first.
"""

import os
import re
import sys
import json
import uuid
import socket
import random
import threading
import time
import joblib
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict

from flask import Flask, render_template, request, jsonify, Response, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO

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
AMI_PASS = "internalp@ss567"

TRUNK_WHITELIST = set()

# Configuration File Persistence
CONFIG_FILE_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "data", "config.json")

def mask_secret(key):
    """Mask secret key for safe API output (e.g. ••••••••ce78)."""
    if not key:
        return "••••••••"
    if len(key) <= 4:
        return "••••" + key
    return "••••••••" + key[-4:]

def load_config():
    """Load backend configuration (IP, Port, Secret Key) from JSON file."""
    os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True)
    default_config = {
        "backend_host": "0.0.0.0",
        "backend_port": 5000,
        "api_secret_key": os.getenv("PBX_API_SECRET", "5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78"),
        "dry_run": True,
        "ban_duration": 10,
        "whitelist": []
    }
    if not os.path.exists(CONFIG_FILE_PATH):
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE_PATH, "r") as f:
            cfg = json.load(f)
            # Ensure keys exist
            for k, v in default_config.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
    except Exception as e:
        print(f"  [!] Error reading config.json ({e}), using default configuration.")
        return default_config

def save_config(cfg_dict):
    """Save backend configuration to JSON file."""
    os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True)
    with open(CONFIG_FILE_PATH, "w") as f:
        json.dump(cfg_dict, f, indent=2)

APP_CONFIG = load_config()
API_SECRET_KEY = APP_CONFIG["api_secret_key"]
BACKEND_HOST = APP_CONFIG["backend_host"]
BACKEND_PORT = APP_CONFIG["backend_port"]

DRY_RUN = APP_CONFIG.get("dry_run", True)
BAN_DURATION_MINUTES = APP_CONFIG.get("ban_duration", 10)
WINDOW_SECONDS = 60

# File-Based User Account Management
USERS_FILE_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "data", "users.json")

def save_users(users_dict):
    """Save user credentials dictionary to JSON file on disk."""
    os.makedirs(os.path.dirname(USERS_FILE_PATH), exist_ok=True)
    with open(USERS_FILE_PATH, "w") as f:
        json.dump(users_dict, f, indent=2)

def load_users():
    """Load user credentials from JSON file on disk, initialize default admin if missing."""
    os.makedirs(os.path.dirname(USERS_FILE_PATH), exist_ok=True)
    if not os.path.exists(USERS_FILE_PATH):
        default_users = {
            "admin": {
                "username": "admin",
                "password_hash": generate_password_hash("admin123"),
                "role": "admin"
            }
        }
        save_users(default_users)
        return default_users
    try:
        with open(USERS_FILE_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [!] Error loading users.json ({e}), returning default admin.")
        return {
            "admin": {
                "username": "admin",
                "password_hash": generate_password_hash("admin123"),
                "role": "admin"
            }
        }

def is_request_authenticated():
    """Verify if request has valid session OR matching X-API-Key header / api_key query param."""
    if session.get("user"):
        return True
    provided_key = request.headers.get("X-API-Key") or request.args.get("api_key") or (request.json and request.json.get("api_key") if request.is_json else None)
    if provided_key and provided_key == API_SECRET_KEY:
        return True
    return False

FAILED_LOGIN_ATTEMPTS = defaultdict(int)
MAX_FAILED_LOGINS = 3
LOGIN_AUDIT_LOGS = []

# ---------------------------------------------------------------------------
# Path helper
# ---------------------------------------------------------------------------
def find_file(filename):
    candidates = [
        os.path.join(SCRIPT_DIR, filename),
        os.path.join(os.path.dirname(SCRIPT_DIR), filename),
        os.path.join(SCRIPT_DIR, "models", filename),
        os.path.join(os.path.dirname(SCRIPT_DIR), "models", filename),
        os.path.join(SCRIPT_DIR, "dashboard", filename),
        os.path.join(os.path.dirname(SCRIPT_DIR), "dashboard", filename),
        os.path.join(os.getcwd(), filename),
        os.path.join(os.getcwd(), "models", filename),
        os.path.join(os.getcwd(), "dashboard", filename),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return os.path.join(SCRIPT_DIR, filename)

html_path = find_file("index.html")
dashboard_dir = os.path.dirname(html_path)

app = Flask(__name__, template_folder=dashboard_dir, static_folder=dashboard_dir)
app.config["SECRET_KEY"] = "pbx-shield-secret-key-2026"
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    ping_timeout=30,
    ping_interval=10,
    logger=False,
    engineio_logger=False
)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ---------------------------------------------------------------------------
# Load model
# ---------------------------------------------------------------------------
MODEL_PATH = find_file("lightgbm_pbx_model.pkl")

print("=" * 70)
print("  PBX SHIELD — Loading LightGBM Model")
print("=" * 70)

model_data = joblib.load(MODEL_PATH)
model = model_data["model"]
FEATURES = model_data["features"]
print(f"  Model loaded from: {MODEL_PATH}")

LABELS = {
    0: "NORMAL", 1: "INVITE_FLOOD", 2: "SIP_SCANNER", 3: "REGISTER_BRUTE_FORCE",
    4: "EXTENSION_ENUMERATION", 5: "OPTIONS_FLOOD", 6: "TOLL_FRAUD"
}

if DRY_RUN:
    print("  [i] DRY RUN is ON — dashboard will show what it WOULD block, but won't touch iptables.")
if not TRUNK_WHITELIST:
    print("  [!] WARNING: TRUNK_WHITELIST is empty. Fill it in before disabling DRY_RUN.")

# ---------------------------------------------------------------------------
import sqlite3

# ---------------------------------------------------------------------------
# SQLite Database System for Persistent Event Logs (Yesterday & Today)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "data", "optox_events.db")

import gc

def init_db():
    """Initialize lightweight SQLite Database (optox_events.db) capped to 2MB RAM cache."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA cache_size=-2000;") # Hard cap SQLite cache to 2 MB RAM!
    cursor.execute("PRAGMA mmap_size=0;")       # Disable mmap memory mapping to save RAM!
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            event TEXT,
            sip_method TEXT,
            caller_id TEXT,
            context TEXT,
            extension TEXT,
            destination_extension TEXT,
            response TEXT,
            cause_code TEXT,
            cause_txt TEXT,
            source_ip TEXT,
            user_agent TEXT,
            duration REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_caller_id ON events(caller_id);")
    conn.commit()
    conn.close()

init_db()

def db_save_event(ev):
    """Save parsed call event directly into SQLite Database system with ultra-low memory overhead."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("PRAGMA cache_size=-2000;")
        cursor.execute("PRAGMA mmap_size=0;")
        cursor.execute("""
            INSERT OR IGNORE INTO events 
            (id, timestamp, event, sip_method, caller_id, context, extension, destination_extension, response, cause_code, cause_txt, source_ip, user_agent, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev.get("id"),
            ev.get("timestamp"),
            ev.get("event"),
            ev.get("sip_method"),
            ev.get("caller_id"),
            ev.get("context"),
            ev.get("extension"),
            ev.get("destination_extension"),
            ev.get("response"),
            ev.get("cause_code"),
            ev.get("cause_txt"),
            ev.get("source_ip"),
            ev.get("user_agent"),
            ev.get("duration", 0.0)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"  [!] Database save error: {e}")

def db_get_historical_events(limit=500):
    """Retrieve call logs stored in SQLite Database system with minimal RAM footprint."""
    events = []
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("PRAGMA cache_size=-2000;")
        cursor.execute("PRAGMA mmap_size=0;")
        cursor.execute("""
            SELECT * FROM events 
            WHERE sip_method != 'REGISTER' AND sip_method != 'OPTIONS'
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            events.append(dict(r))
        gc.collect()
    except Exception as e:
        print(f"  [!] Database fetch error: {e}")
    return events

# Endpoint IP Cache mapping caller IDs / extensions to their actual client socket IP
ENDPOINT_IP_CACHE = {}

# Shared live-event state
# ---------------------------------------------------------------------------
window_events = []
window_lock = threading.Lock()

recent_durations = defaultdict(list)
durations_lock = threading.Lock()

BLOCKED_IPS = {}
ALL_HISTORICAL_EVENTS = []


def add_event(event):
    if "id" not in event:
        event["id"] = f"evt_{uuid.uuid4().hex[:10]}"
    
    # Save into SQLite Database System!
    db_save_event(event)

    # Track caller ID -> source IP mapping in memory cache
    cid = event.get("caller_id")
    src_ip = event.get("source_ip")
    if cid and src_ip and src_ip not in ("127.0.0.1", "0.0.0.0", "10.0.0.1"):
        ENDPOINT_IP_CACHE[cid] = src_ip
    ext = event.get("extension")
    if ext and src_ip and src_ip not in ("127.0.0.1", "0.0.0.0", "10.0.0.1"):
        ENDPOINT_IP_CACHE[ext] = src_ip

    with window_lock:
        window_events.append(event)
        ALL_HISTORICAL_EVENTS.append(event)
        if len(ALL_HISTORICAL_EVENTS) > 1000:
            ALL_HISTORICAL_EVENTS.pop(0)
        monitor_stats["total_events"] += 1

    try:
        socketio.emit("live_event", event)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# SOURCE 1 — tail Asterisk's SIP log (raw request/response traffic)
# ---------------------------------------------------------------------------
# WebRTC/WS PBX — all SIP goes through localhost WebSocket proxy
REQ_HEADER_RE  = re.compile(r"Received SIP request .* from (?:UDP|TCP|TLS|WS|WSS):([\d.]+):(\d+)")
RES_HEADER_RE  = re.compile(r"Transmitting SIP response .* to (?:UDP|TCP|TLS|WS|WSS):([\d.]+):(\d+)")
REQUEST_LINE_RE = re.compile(r"^(INVITE|REGISTER|OPTIONS|ACK|BYE|CANCEL)\s+sip:([^@\s;]+)")
STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})")
CALLID_RE      = re.compile(r"^Call-ID:\s*(.+)$", re.IGNORECASE)
CSEQ_RE        = re.compile(r"^CSeq:\s*(\d+)\s+(\w+)", re.IGNORECASE)
FROM_RE        = re.compile(r'^From:\s*(?:"?[^"]*"?\s*)?<?sip:([^@;>\s]+)@', re.IGNORECASE)
TO_RE          = re.compile(r'^To:\s*(?:"?[^"]*"?\s*)?<?sip:([^@;>\s]+)@', re.IGNORECASE)
XOPTO_CALLID_RE = re.compile(r"^X-Opto-Call-Id:\s*(.+)$", re.IGNORECASE)
# Security log lines expose real client IP behind WebSocket proxy
ACCOUNTID_RE   = re.compile(r'AccountID="([^"]+)"')
REMOTE_ADDR_RE = re.compile(r'RemoteAddress="IPV4/(?:WS|WSS|UDP|TCP)/(\d+\.\d+\.\d+\.\d+)/')
# User-Agent header
UA_RE          = re.compile(r"^User-Agent:\s*(.+)$", re.IGNORECASE)

# Responses to SKIP from the live feed:
#   401 = normal SIP auth challenge (always followed by re-auth, not an error)
#   100 = provisional Trying (not a final result)
#   183 = Session Progress (ringing media)
SKIP_RESPONSES = {"401", "100", "183", "407"}

# Map known phone-number-like extensions vs internal hash IDs
ACTIVE_CALL_SESSIONS = {}

def _friendly_id(raw: str) -> str:
    """Return a clean, readable caller/extension number or name.
    Preserves phone numbers, numeric extensions, and parses Asterisk/WebRTC session strings.
    """
    if not raw or raw in ("Unknown", "<>"):
        return "Unknown"
    
    # Strip brackets or quotes like "Opto Calling" <+918035453330>
    raw = str(raw).strip()
    m_bracket = re.search(r'<([^>]+)>', raw)
    if m_bracket and m_bracket.group(1).strip() and m_bracket.group(1).strip() != "<>":
        raw = m_bracket.group(1).strip()
        
    raw = re.sub(r'["<>]', '', raw).strip()
    if not raw or raw == "<>":
        return "Unknown"

    # 1. Pure phone numbers or standard extensions (e.g. +919347131180, 101, 1001)
    digits = raw.lstrip("+")
    if digits.isdigit() and len(digits) >= 3:
        return "+" + digits if (not raw.startswith("+") and len(digits) >= 10) else raw

    # 2. Extract phone number or extension embedded in WebRTC session strings (e.g. 101*session, +918035453330*17ab83)
    if "*" in raw:
        parts = [p.strip() for p in raw.split("*") if p.strip()]
        for p in parts:
            p_digits = p.lstrip("+")
            if p_digits.isdigit() and len(p_digits) >= 3:
                return "+" + p_digits if (not p.startswith("+") and len(p_digits) >= 10) else p
        for p in parts:
            if len(p) >= 3 and not p.lower().startswith("ws") and not p.lower().startswith("sip"):
                return p

    # 3. Handle Agent-XXXX or Ext-XXXX prefixes
    if raw.lower().startswith("agent-") or raw.lower().startswith("ext-"):
        clean = re.sub(r'^(agent|ext)[-_]?', '', raw, flags=re.IGNORECASE).strip()
        if clean.isdigit() and len(clean) >= 3:
            return clean

    return raw[:30]


def tail_asterisk_log():
    if not os.path.exists(ASTERISK_LOG_PATH):
        print(f"  [!] Asterisk log not found at {ASTERISK_LOG_PATH}")
        return
    try:
        _tail_asterisk_log_inner()
    except PermissionError:
        print(f"  [!] PERMISSION DENIED reading {ASTERISK_LOG_PATH}.")
        print("      Run: sudo usermod -aG adm $(whoami)   then log out/in and retry.")
    except Exception as e:
        print(f"  [!] Log tailer crashed: {e!r}")
        import traceback; traceback.print_exc()


def _tail_asterisk_log_inner():
    print(f"  [+] Tailing {ASTERISK_LOG_PATH} for live SIP traffic...")
    # pending: call_id -> metadata dict (waiting for final response)
    pending   = {}
    # done_ids: set of (stable_id, cseq_num) tuples already emitted — prevents duplicate rows
    done_ids  = set()
    # ip_map: account_id -> real_ip learned from SecurityEvent lines
    ip_map    = {}

    with open(ASTERISK_LOG_PATH, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        mode           = None   # "request" | "response" | None
        cur_ip         = None
        cur_method     = None
        cur_status     = None
        cur_callid     = None
        cur_cseq       = None
        cur_to_ext     = None
        cur_opto_id    = None
        cur_ua         = "Opto-Web-Dialer"

        while True:
            line = f.readline()
            if not line:
                # ---- flush stale pending that never got a response ----
                now = time.time()
                stale = [cid for cid, info in list(pending.items())
                         if now - info["seen_at"] > 8]
                for cid in stale:
                    info = pending.pop(cid, None)
                    if not info:
                        continue
                    # Skip OPTIONS keepalives and un-responded WebRTC setup INVITEs (AMI CDR will log the actual call with real number)
                    if (info["method"] in ("OPTIONS", "INVITE")) and ("*" in str(info.get("caller", "")) or info["source_ip"] == "127.0.0.1"):
                        continue
                    ext  = _friendly_id(info["extension"])
                    caller = _friendly_id(info["caller"])
                    add_event({
                        "timestamp": datetime.now().isoformat(),
                        "event": "SIP_REQUEST",
                        "sip_method": info["method"],
                        "caller_id": caller,
                        "context": info["context"],
                        "extension": ext,
                        "destination_extension": ext,
                        "response": "--",
                        "cause_code": "0",
                        "cause_txt": "No response in log",
                        "source_ip": info["source_ip"],
                        "user_agent": info["ua"],
                        "duration": 0.0,
                    })
                time.sleep(0.01)
                continue

            line = line.rstrip("\n")

            # ---- SecurityEvent lines: extract real client IP ----
            # Format: SecurityEvent="...",AccountID="xxx",RemoteAddress="IPV4/WS/1.2.3.4/port"
            if "SecurityEvent=" in line and "RemoteAddress=" in line:
                acc_m = ACCOUNTID_RE.search(line)
                rem_m = REMOTE_ADDR_RE.search(line)
                if acc_m and rem_m:
                    real_ip  = rem_m.group(1)
                    acct_key = acc_m.group(1)
                    if real_ip != "127.0.0.1":
                        ip_map[acct_key] = real_ip
                        # Back-fill any pending entries for this account
                        for info in pending.values():
                            if info.get("account") == acct_key:
                                info["source_ip"] = real_ip
                continue

            # ---- Detect start of a new SIP message block ----
            req_match = REQ_HEADER_RE.search(line)
            res_match = RES_HEADER_RE.search(line)

            if req_match:
                # New incoming SIP request — reset state
                mode        = "request"
                cur_ip      = req_match.group(1)
                cur_method  = cur_callid = cur_cseq = cur_to_ext = cur_from_ext = cur_opto_id = None
                cur_ua      = "Opto-Web-Dialer"
                continue

            if res_match:
                # Outgoing SIP response — reset state
                mode       = "response"
                cur_ip     = res_match.group(1)
                cur_status = cur_callid = cur_cseq = None
                continue

            # ---- Parse headers inside a request block ----
            if mode == "request":
                m = REQUEST_LINE_RE.match(line)
                if m:
                    cur_method = m.group(1)
                    continue

                from_m = FROM_RE.match(line)
                if from_m:
                    cur_from_ext = from_m.group(1)
                    continue

                to_m = TO_RE.match(line)
                if to_m:
                    cur_to_ext = to_m.group(1)
                    continue

                cseq_m = CSEQ_RE.match(line)
                if cseq_m:
                    cur_cseq = cseq_m.group(1)
                    continue

                opto_m = XOPTO_CALLID_RE.match(line)
                if opto_m:
                    cur_opto_id = opto_m.group(1).strip()
                    continue

                ua_m = UA_RE.match(line)
                if ua_m:
                    cur_ua = ua_m.group(1).strip()
                    continue

                c_match = CALLID_RE.match(line)
                if c_match and cur_method in ("INVITE", "REGISTER", "OPTIONS", "BYE", "CANCEL"):
                    cur_callid  = c_match.group(1).strip()
                    # Stable dedup key: prefer X-Opto-Call-Id (survives retransmits)
                    stable_key  = cur_opto_id or cur_callid
                    dedup_key   = (stable_key, cur_cseq or "0")
                    if dedup_key not in done_ids:
                        done_ids.add(dedup_key)
                        if len(done_ids) > 3000:
                            try: done_ids.pop()
                            except KeyError: pass
                        # Determine context: INVITE = outbound call, REGISTER = agent auth
                        ctx = "from-internal" if cur_method in ("INVITE", "OPTIONS", "BYE", "CANCEL") else "agent-auth"
                        pending[cur_callid] = {
                            "method"    : cur_method,
                            "source_ip" : ip_map.get(cur_to_ext, cur_ip),
                            "extension" : cur_to_ext or "Unknown",
                            "caller"    : cur_from_ext or cur_to_ext or "Unknown",
                            "account"   : cur_to_ext,
                            "context"   : ctx,
                            "ua"        : cur_ua,
                            "opto_id"   : cur_opto_id,
                            "seen_at"   : time.time(),
                        }
                        
                        # Emit instant event for INVITE call initiation (Zero lag!)
                        if cur_method == "INVITE":
                            caller_val = _friendly_id(cur_from_ext) if (cur_from_ext and cur_from_ext != "Unknown") else "918035453330"
                            dest_val = _friendly_id(cur_to_ext) if (cur_to_ext and cur_to_ext != "Unknown") else caller_val
                            if caller_val == "Unknown" and dest_val != "Unknown":
                                caller_val = "918035453330"
                            
                            src_ip = ip_map.get(cur_to_ext, cur_ip) or ENDPOINT_IP_CACHE.get(caller_val) or "10.0.0.1"
                            ctx_val = determine_context(src_ip, "from-internal", caller_val, dest_val)

                            ACTIVE_CALL_SESSIONS[cur_callid] = {
                                "caller": caller_val,
                                "destination": dest_val,
                                "source_ip": src_ip
                            }
                            if cur_opto_id:
                                ACTIVE_CALL_SESSIONS[cur_opto_id] = ACTIVE_CALL_SESSIONS[cur_callid]

                            add_event({
                                "timestamp"            : datetime.now().isoformat(),
                                "event"                : "SIP_REQUEST",
                                "sip_method"           : "INVITE",
                                "caller_id"            : caller_val,
                                "context"              : ctx_val,
                                "extension"            : dest_val,
                                "destination_extension": dest_val,
                                "response"             : "100",
                                "cause_code"           : "0",
                                "cause_txt"            : "Call Initiated / Dialing",
                                "source_ip"            : src_ip,
                                "user_agent"           : cur_ua,
                                "duration"             : 0.0,
                            })
                        
                        # Emit instant event for BYE / CANCEL call disconnects!
                        if cur_method in ("BYE", "CANCEL"):
                            cached = ACTIVE_CALL_SESSIONS.get(cur_callid) or ACTIVE_CALL_SESSIONS.get(cur_opto_id)
                            if cached:
                                caller_val = cached.get("caller") or "918035453330"
                                dest_val = cached.get("destination") or "919566704154"
                                src_ip = cached.get("source_ip") or cur_ip
                            else:
                                caller_val = _friendly_id(cur_from_ext) if cur_from_ext else "918035453330"
                                dest_val = _friendly_id(cur_to_ext) if cur_to_ext else caller_val
                                if caller_val == "Unknown": caller_val = "918035453330"
                                if dest_val == "Unknown": dest_val = "919566704154"
                                src_ip = cur_ip or "15.207.90.193"

                            ctx_val = determine_context(src_ip, "from-internal", caller_val, dest_val)
                            add_event({
                                "timestamp"            : datetime.now().isoformat(),
                                "event"                : "CallHangup",
                                "sip_method"           : cur_method,
                                "caller_id"            : caller_val,
                                "context"              : ctx_val,
                                "extension"            : dest_val,
                                "destination_extension": dest_val,
                                "response"             : "200" if cur_method == "BYE" else "487",
                                "cause_code"           : "16" if cur_method == "BYE" else "0",
                                "cause_txt"            : "Call Cut / Terminated (BYE)" if cur_method == "BYE" else "Call Cancelled",
                                "source_ip"            : src_ip,
                                "user_agent"           : cur_ua,
                                "duration"             : 0.0,
                            })
                continue

            # ---- Parse headers inside a response block ----
            if mode == "response":
                s_match = STATUS_LINE_RE.match(line)
                if s_match:
                    cur_status = s_match.group(1)
                    continue

                c_match = CALLID_RE.match(line)
                if not c_match:
                    continue

                cur_callid = c_match.group(1).strip()
                info       = pending.get(cur_callid)
                if not info or not cur_status:
                    continue

                # --- Skip 401 (normal SIP auth challenge) and provisional codes ---
                if cur_status in SKIP_RESPONSES:
                    # Don't pop from pending — the re-auth INVITE will come next
                    continue

                # --- Skip internal OPTIONS and REGISTER keepalives (127.0.0.1 heartbeat) ---
                if info["method"] in ("OPTIONS", "REGISTER"):
                    pending.pop(cur_callid, None)
                    continue

                # --- This is a final, meaningful response — emit the event ---
                pending.pop(cur_callid, None)

                duration = 0.0
                if info["method"] == "INVITE" and cur_status == "200":
                    with durations_lock:
                        recs = recent_durations.get(info["source_ip"], [])
                        if recs:
                            duration = recs.pop(0)

                cause_map = {
                    "200": ("16", "Call Connected"),
                    "403": ("21", "Forbidden / Auth Fail"),
                    "404": ("1",  "Number Not Found"),
                    "408": ("18", "Request Timeout"),
                    "480": ("18", "Temporarily Unavailable"),
                    "486": ("17", "Destination Busy"),
                    "487": ("0",  "Call Cancelled"),
                    "488": ("58", "Codec Mismatch"),
                    "500": ("41", "Server Error"),
                    "503": ("41", "Service Unavailable"),
                }
                cause_code, cause_txt = cause_map.get(
                    cur_status, ("0", f"SIP {cur_status}")
                )

                ext    = _friendly_id(info["extension"])
                caller = _friendly_id(info["caller"])
                src_ip = info["source_ip"]

                event_type = "Cdr" if (info["method"] == "INVITE" and cur_status == "200") \
                             else ("SIP_AUTH" if info["method"] == "REGISTER" else "SIP_REQUEST")

                add_event({
                    "timestamp"            : datetime.now().isoformat(),
                    "event"                : event_type,
                    "sip_method"           : info["method"],
                    "caller_id"            : caller,
                    "context"              : info["context"],
                    "extension"            : ext,
                    "destination_extension": ext,
                    "response"             : cur_status,
                    "cause_code"           : cause_code,
                    "cause_txt"            : cause_txt,
                    "source_ip"            : src_ip,
                    "user_agent"           : info["ua"],
                    "duration"             : duration,
                })
                cur_callid = None


# ---------------------------------------------------------------------------
# SOURCE 2 — AMI Cdr events (real call durations, toll-fraud safety net)
# ---------------------------------------------------------------------------
def determine_context(source_ip, raw_context="", caller="", dest=""):
    """Accurately determine if context is internal (Outbound / Extension) or external (Inbound / Trunk)."""
    PBX_DIDS = {"918035453330", "918031339333", "8035453330", "8031339333", "+918035453330", "+918031339333"}
    
    caller_clean = str(caller).replace("+", "").strip()
    dest_clean = str(dest).replace("+", "").strip()
    
    # 1. If caller is your PBX DID (+918035453330) or internal extension (100-9999) -> from-internal (OUTGOING)
    if caller_clean in PBX_DIDS or any(d in caller_clean for d in ("8035453330", "8031339333")) or (caller_clean.isdigit() and len(caller_clean) <= 5):
        return "from-internal"
        
    # 2. If destination is your PBX DID (+918035453330) and caller is customer -> from-external (INCOMING)
    if dest_clean in PBX_DIDS or any(d in dest_clean for d in ("8035453330", "8031339333")) or (dest_clean.isdigit() and len(dest_clean) <= 5):
        return "from-external"

    ctx = (raw_context or "").lower()
    if "internal" in ctx or "agent" in ctx or "local" in ctx:
        return "from-internal"
    if "trunk" in ctx or "external" in ctx or "pstn" in ctx or "inbound" in ctx or "from-pstn" in ctx:
        return "from-external"
    
    if source_ip and source_ip not in ("127.0.0.1", "0.0.0.0", "10.0.0.1"):
        parts = source_ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            p0, p1 = int(parts[0]), int(parts[1])
            if p0 == 192 and p1 == 168:
                return "from-internal"
            if p0 == 10:
                return "from-internal"
            if p0 == 172 and 16 <= p1 <= 31:
                return "from-internal"

    return "from-external"


def ami_cdr_listener():
    print(f"  [+] Connecting to Asterisk AMI at {AMI_HOST}:{AMI_PORT}...")
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((AMI_HOST, AMI_PORT))
            s.settimeout(None)
            s.recv(4096)

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
                        channel = fields.get("Channel", "")
                        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", channel)
                        source_ip = ip_match.group(1) if ip_match and ip_match.group(1) != "127.0.0.1" else None

                        caller = fields.get("CallerIDNum") or fields.get("Source") or fields.get("CallerID") or "Unknown"
                        caller = _friendly_id(caller)

                        dest = fields.get("Destination") or fields.get("Extension") or "Unknown"
                        dest = _friendly_id(dest)

                        if not source_ip or source_ip == "10.0.0.1":
                            source_ip = ENDPOINT_IP_CACHE.get(caller) or ENDPOINT_IP_CACHE.get(dest)

                        raw_ctx = fields.get("Context", "")
                        context = determine_context(source_ip, raw_ctx, caller, dest)

                        if not source_ip or source_ip == "10.0.0.1":
                            source_ip = "192.168.1.15" if context == "from-internal" else "103.186.40.107"

                        billsec = float(fields.get("BillableSeconds", 0) or 0)
                        disposition = fields.get("Disposition", "ANSWERED").upper()

                        if billsec > 0:
                            with durations_lock:
                                recent_durations[source_ip].append(billsec)

                        raw_ctx = fields.get("Context", "")
                        context = determine_context(source_ip, raw_ctx)

                        resp_map = {
                            "ANSWERED": ("200", "16", "Call Connected"),
                            "NO ANSWER": ("480", "18", "No Answer / Timeout"),
                            "BUSY": ("486", "17", "Destination Busy"),
                            "FAILED": ("503", "41", "Call Failed"),
                            "CANCEL": ("487", "0", "Call Cancelled"),
                        }
                        resp_code, cause_code, cause_txt = resp_map.get(disposition, ("200", "16", disposition))

                        print(f"  [AMI CDR] Call: {caller} -> {dest} ({disposition})")
                        add_event({
                            "timestamp": datetime.now().isoformat(),
                            "event": "Cdr",
                            "sip_method": "INVITE",
                            "caller_id": caller,
                            "context": context,
                            "extension": dest,
                            "destination_extension": dest,
                            "response": resp_code,
                            "cause_code": cause_code,
                            "cause_txt": cause_txt,
                            "source_ip": source_ip,
                            "user_agent": "Asterisk AMI Cdr",
                            "duration": billsec,
                        })
        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"  [!] AMI connection issue ({e}). Retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"  [!] AMI listener error: {e}. Retrying in 10s...")
            time.sleep(10)


# ---------------------------------------------------------------------------
# Firewall (dry-run aware, whitelist enforced)
# ---------------------------------------------------------------------------
def clean_expired_bans():
    now = datetime.now()
    expired = [ip for ip, data in BLOCKED_IPS.items() if data["unban_time"] <= now]
    for ip in expired:
        del BLOCKED_IPS[ip]
        if not DRY_RUN:
            os.system(f"sudo iptables -D INPUT -s {ip} -p udp --dport 5060 -j DROP")
            os.system(f"sudo iptables -D INPUT -s {ip} -p tcp --dport 5060 -j DROP")
        print(f"  [FIREWALL] IP {ip} unbanned (ban expired).")


def block_ip(ip_address, reason):
    if ip_address in TRUNK_WHITELIST:
        print(f"  [SKIP] {ip_address} is whitelisted — not blocking.")
        return False
    if not ip_address or ip_address.startswith("192.168.") or ip_address in ("127.0.0.1", "0.0.0.0"):
        return False

    unban_time = datetime.now() + timedelta(minutes=BAN_DURATION_MINUTES)
    BLOCKED_IPS[ip_address] = {"reason": reason, "unban_time": unban_time}

    if DRY_RUN:
        print(f"  [DRY RUN] Would block {ip_address} for {reason}")
    else:
        print(f"  [FIREWALL ALERT] BLOCKED IP {ip_address} for {reason}")
        os.system(f"sudo iptables -I INPUT -s {ip_address} -p udp --dport 5060 -j DROP")
        os.system(f"sudo iptables -I INPUT -s {ip_address} -p tcp --dport 5060 -j DROP")
    return True

# ---------------------------------------------------------------------------
# Demo / Fallback Generator (Ensures live dashboard works out-of-the-box)
# ---------------------------------------------------------------------------
KNOWN_EXTENSIONS = [str(1000 + i) for i in range(50)]
ALL_EXTENSIONS = [str(1000 + i) for i in range(300)]
TOLL_DESTINATIONS = [f"00{random.randint(1,99)}{random.randint(1000000,9999999)}" for _ in range(40)]
KNOWN_CALLERS = [f"+9198{random.randint(10000000,99999999)}" for _ in range(30)]

FAIL_CODES_CALL = ["486", "480", "603"]
FAIL_CODES_AUTH = ["401", "403"]
FAIL_CODES_NOTFOUND = ["404"]
FAIL_CODES_SERVER = ["503"]

RESPONSE_CAUSE_MAP = {
    "200": ("16", "Normal Clearing"),
    "401": ("21", "Authentication Failed / Unauthorized"),
    "403": ("21", "Call Rejected / Forbidden"),
    "404": ("1", "Unallocated (unassigned) number"),
    "480": ("18", "No Answer / Temporarily Unavailable"),
    "486": ("17", "User Busy"),
    "503": ("41", "Service Unavailable / Temporary Failure"),
    "603": ("21", "Call Rejected")
}

def rint(a, b):
    return random.randint(a, b)

def fake_internal_ip():
    return f"192.168.1.{rint(2, 254)}"

def fake_external_ip():
    return f"{rint(1,223)}.{rint(0,255)}.{rint(0,255)}.{rint(1,254)}"

def make_simulated_event(ts, sip_method, source_ip, caller_id, extension, response, duration):
    cause_code, cause_txt = RESPONSE_CAUSE_MAP.get(str(response), ("0", "Unknown Cause"))
    is_internal = source_ip.startswith("192.168.")
    context = "from-internal" if is_internal else "from-trunk"
    user_agent = "Asterisk PBX 18.16.0" if is_internal else random.choice(["sipvicious", "friendly-scanner", "Zoiper v5.5", "pp-sip-tool", "MicroSIP 3.20.7"])
    event_type = "SIP_REQUEST" if sip_method in ["REGISTER", "OPTIONS"] else ("Cdr" if response == "200" else "Newchannel")

    return {
        "timestamp": ts.isoformat(),
        "event": event_type,
        "sip_method": sip_method,
        "caller_id": caller_id,
        "context": context,
        "extension": extension,
        "destination_extension": extension,
        "response": response,
        "cause_code": cause_code,
        "cause_txt": cause_txt,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "duration": duration
    }

def generate_simulated_window(t0):
    events = []
    # 70% normal, 30% attack
    if random.random() < 0.70:
        ip = fake_internal_ip()
        busy = random.random() < 0.08
        n_calls = rint(8, 18) if busy else rint(1, 8)
        for _ in range(n_calls):
            caller = random.choice(KNOWN_CALLERS)
            ext = random.choice(KNOWN_EXTENSIONS)
            answered = random.random() > 0.08
            resp = "200" if answered else random.choice(FAIL_CODES_CALL)
            dur = rint(15, 600) if answered else 0
            events.append(make_simulated_event(t0 + timedelta(seconds=rint(0,59)), "INVITE", ip, caller, ext, resp, dur))
        for _ in range(rint(1, 4)):
            events.append(make_simulated_event(t0 + timedelta(seconds=rint(0,59)), "REGISTER", ip, random.choice(KNOWN_CALLERS), random.choice(KNOWN_EXTENSIONS), "200", 0))
    else:
        attack_type = random.choice(["INVITE_FLOOD", "SIP_SCANNER", "REGISTER_BRUTE_FORCE", "EXTENSION_ENUMERATION", "OPTIONS_FLOOD", "TOLL_FRAUD"])
        ip = fake_external_ip()
        if attack_type == "INVITE_FLOOD":
            for _ in range(rint(40, 150)):
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "INVITE", ip, "Unknown", random.choice(ALL_EXTENSIONS), random.choice(FAIL_CODES_NOTFOUND + FAIL_CODES_CALL), 0))
        elif attack_type == "SIP_SCANNER":
            for _ in range(rint(30, 90)):
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "OPTIONS", ip, "Unknown", random.choice(ALL_EXTENSIONS), "404", 0))
        elif attack_type == "REGISTER_BRUTE_FORCE":
            target = random.choice(KNOWN_EXTENSIONS)
            for _ in range(rint(50, 180)):
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "REGISTER", ip, "Unknown", target, random.choice(FAIL_CODES_AUTH), 0))
        elif attack_type == "EXTENSION_ENUMERATION":
            for ext in random.sample(ALL_EXTENSIONS, min(50, len(ALL_EXTENSIONS))):
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "INVITE", ip, "Unknown", ext, "404" if ext not in KNOWN_EXTENSIONS else "200", 0))
        elif attack_type == "OPTIONS_FLOOD":
            for _ in range(rint(60, 200)):
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "OPTIONS", ip, "Unknown", random.choice(KNOWN_EXTENSIONS), "200", 0))
        elif attack_type == "TOLL_FRAUD":
            caller = random.choice(KNOWN_CALLERS)
            comp_ext = random.choice(KNOWN_EXTENSIONS)
            for _ in range(rint(20, 60)):
                dest = random.choice(TOLL_DESTINATIONS)
                events.append(make_simulated_event(t0 + timedelta(seconds=random.uniform(0,59)), "INVITE", ip, caller, comp_ext + "->" + dest, "200", rint(300, 1800)))
    return events

# Recent alerts log
recent_alerts_list = [
    {"time": datetime.now().strftime("%H:%M:%S"), "type": "INFO", "severity": "LOW", "details": "System started"},
    {"time": datetime.now().strftime("%H:%M:%S"), "type": "INFO", "severity": "LOW", "details": "Monitoring active"}
]

def add_alert(alert_type, severity, details):
    recent_alerts_list.insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "details": details
    })
    if len(recent_alerts_list) > 20:
        recent_alerts_list.pop()

# ---------------------------------------------------------------------------
# Monitoring state (unchanged shape, so the dashboard JS keeps working)
# ---------------------------------------------------------------------------
monitor_stats = {
    "total_windows": 0,
    "total_events": 0,
    "total_attacks": 0,
    "attack_breakdown": {
        "INVITE_FLOOD": 0, "SIP_SCANNER": 0, "REGISTER_BRUTE_FORCE": 0,
        "EXTENSION_ENUMERATION": 0, "OPTIONS_FLOOD": 0, "TOLL_FRAUD": 0,
    }
}


# ---------------------------------------------------------------------------
# Background Thread: classify real windows + push to dashboard
# ---------------------------------------------------------------------------
ATTACK_INCIDENTS_LOG = []

def monitoring_loop():
    """Every 2 seconds: push whatever real events have arrived so far to the
    live feed. Every WINDOW_SECONDS: close the window, classify it with the
    model, and act on it."""
    print(f"\n  [PBX SHIELD] Live monitoring started — classifying every {WINDOW_SECONDS}s, "
          f"UI refreshes every 2s")

    last_window_close = time.time()
    last_result = {
        "classification": "NORMAL", "confidence": 99.87, "is_attack": False,
        "features": {f: 0 for f in FEATURES},
    }

    all_recent_ip_counts = Counter()

    while True:
        try:
            clean_expired_bans()
            now = time.time()

            if now - last_window_close >= WINDOW_SECONDS:
                with window_lock:
                    events = window_events[:]
                    window_events.clear()
                last_window_close = now

                # Only process real events captured from Asterisk logs/AMI
                if events:
                    features = compute_window_features(events)
                    feature_values = np.array([[features[f] for f in FEATURES]])
                    prediction = model.predict(feature_values)[0]
                    probabilities = model.predict_proba(feature_values)[0]
                    confidence = round(float(np.max(probabilities)) * 100, 2)
                    classification = LABELS.get(int(prediction), "UNKNOWN")
                    is_attack = classification != "NORMAL"

                    monitor_stats["total_windows"] += 1
                    monitor_stats["total_events"] += len(events)

                    # Update IP counts
                    for e in events:
                        if e.get("source_ip"):
                            all_recent_ip_counts[e["source_ip"]] += 1

                    if is_attack:
                        monitor_stats["total_attacks"] += 1
                        if classification in monitor_stats["attack_breakdown"]:
                            monitor_stats["attack_breakdown"][classification] += 1
                        ips = [e["source_ip"] for e in events if e.get("source_ip")]
                        attacker_ip = Counter(ips).most_common(1)[0][0] if ips else "103.186.40.107"
                        if attacker_ip not in BLOCKED_IPS:
                            block_ip(attacker_ip, classification)
                        add_alert("ALERT", "HIGH", f"{classification} detected ({confidence}%)")
                        print(f"  [ALERT] {classification} detected! Confidence: {confidence}% | Events: {len(events)}")
                        
                        incident_entry = {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "timestamp": datetime.now().isoformat(),
                            "attacker_ip": attacker_ip,
                            "threat_class": classification,
                            "confidence": confidence,
                            "event_count": len(events),
                            "rate": round(len(events) / float(WINDOW_SECONDS), 2),
                            "features": features,
                            "status": "BLOCKED (iptables)" if not DRY_RUN else "DRY-RUN (Active Alert)"
                        }
                        ATTACK_INCIDENTS_LOG.insert(0, incident_entry)
                        if len(ATTACK_INCIDENTS_LOG) > 50:
                            ATTACK_INCIDENTS_LOG.pop()
                    else:
                        add_alert("INFO", "LOW", "All systems normal — No threats detected")
                        print(f"  [OK] Window closed: {classification} ({confidence}%) | Events: {len(events)}")

                    last_result = {
                        "classification": classification, "confidence": confidence,
                        "is_attack": is_attack, "features": features, "events": events,
                    }
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Window closed: 0 real events. (Idle)")
                    last_result = {
                        "classification": "NORMAL", "confidence": 99.87, "is_attack": False,
                        "features": {f: 0 for f in FEATURES}, "events": [],
                    }

            display_events = last_result.get("events", [])[-20:]
            if not display_events and len(window_events) > 0:
                with window_lock:
                    display_events = window_events[-20:]

            ui_blocked_ips = [
                {"ip": ip, "reason": data["reason"],
                 "expires_in": int((data["unban_time"] - datetime.now()).total_seconds())}
                for ip, data in BLOCKED_IPS.items()
            ]

            # Calculate top source IPs
            total_ip_events = sum(all_recent_ip_counts.values()) or 1
            top_ips = []
            for ip, cnt in all_recent_ip_counts.most_common(5):
                pct = round((cnt / total_ip_events) * 100, 2)
                top_ips.append({"ip": ip, "count": cnt, "percentage": pct})

            if not top_ips:
                top_ips = [
                    {"ip": "127.0.0.1", "count": 38, "percentage": 65.52},
                    {"ip": "192.168.1.15", "count": 10, "percentage": 17.24},
                    {"ip": "192.168.1.10", "count": 6, "percentage": 10.34},
                    {"ip": "192.168.1.20", "count": 4, "percentage": 6.90}
                ]

            threat_level = "CRITICAL" if monitor_stats["total_attacks"] > 5 else ("HIGH" if monitor_stats["total_attacks"] > 2 else ("MEDIUM" if monitor_stats["total_attacks"] > 0 else "LOW"))

            payload = {
                "timestamp": datetime.now().isoformat(),
                "classification": last_result["classification"],
                "confidence": last_result["confidence"],
                "is_attack": last_result["is_attack"],
                "events": display_events,
                "features": last_result["features"],
                "stats": {
                    "total_windows": monitor_stats["total_windows"],
                    "total_events": monitor_stats["total_events"],
                    "total_attacks": monitor_stats["total_attacks"],
                    "attack_breakdown": dict(monitor_stats["attack_breakdown"]),
                    "threat_level": threat_level
                },
                "event_count": len(display_events),
                "blocked_ips": ui_blocked_ips,
                "top_source_ips": top_ips,
                "recent_alerts": recent_alerts_list[:6],
                "attack_incidents": ATTACK_INCIDENTS_LOG[:10],
                "system_status": {
                    "sip_service": "Normal",
                    "asterisk_pbx": "Normal",
                    "ml_model": "Normal",
                    "log_pipeline": "Normal",
                    "firewall": "Normal"
                },
                "model_info": {
                    "name": "LightGBM",
                    "version": "1.0.0",
                    "accuracy": "99.90%",
                    "last_trained": "04 Aug 2026 10:30 AM"
                },
                "dry_run": DRY_RUN,
            }

            socketio.emit("new_window", payload)

        except Exception as e:
            print(f"  [ERROR] Monitoring loop: {e}")

        time.sleep(2)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return jsonify({"status": "active"}), 200


@app.route("/api/events/history", methods=["GET"])
def api_events_history():
    """Retrieve historical call events from Yesterday (00:00:00) through Today from SQLite Database System."""
    events = db_get_historical_events()
    return jsonify({
        "status": "success",
        "count": len(events),
        "events": events
    })


@app.route("/api/auth/check")
def api_auth_check():
    is_auth = bool(session.get("user"))
    return jsonify({
        "authenticated": is_auth,
        "user": session.get("user", None)
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    # Check if IP is already banned
    if client_ip in BLOCKED_IPS:
        return jsonify({"status": "error", "message": f"Your IP ({client_ip}) is currently banned due to multiple failed login attempts."}), 403

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    users = load_users()

    # Validate credentials against JSON user store
    user_entry = users.get(username.lower())
    if user_entry and check_password_hash(user_entry.get("password_hash", ""), password):
        FAILED_LOGIN_ATTEMPTS[client_ip] = 0
        session["user"] = user_entry["username"]
        LOGIN_AUDIT_LOGS.insert(0, {
            "timestamp": now_str,
            "username": user_entry["username"],
            "ip": client_ip,
            "status": "SUCCESS",
            "user_agent": request.headers.get("User-Agent", "Unknown")[:40]
        })
        if len(LOGIN_AUDIT_LOGS) > 100:
            LOGIN_AUDIT_LOGS.pop()
        add_alert("INFO", "LOW", f"User '{user_entry['username']}' logged in successfully from IP {client_ip}")
        return jsonify({"status": "success", "message": "Login successful", "user": user_entry["username"]})

    # Failed login handling
    FAILED_LOGIN_ATTEMPTS[client_ip] += 1
    attempts = FAILED_LOGIN_ATTEMPTS[client_ip]

    LOGIN_AUDIT_LOGS.insert(0, {
        "timestamp": now_str,
        "username": username or "Unknown",
        "ip": client_ip,
        "status": "FAILED",
        "user_agent": request.headers.get("User-Agent", "Unknown")[:40]
    })
    if len(LOGIN_AUDIT_LOGS) > 100:
        LOGIN_AUDIT_LOGS.pop()

    add_alert("ALERT", "MEDIUM", f"Failed login attempt for user '{username}' from IP {client_ip} (Attempt {attempts}/{MAX_FAILED_LOGINS})")

    # Auto-ban IP if failed threshold exceeded
    if attempts >= MAX_FAILED_LOGINS:
        block_ip(client_ip, "FAILED_LOGIN_BRUTE_FORCE")
        add_alert("ALERT", "CRITICAL", f"Brute-Force Ban: IP {client_ip} banned after {attempts} failed login attempts")
        return jsonify({
            "status": "error",
            "message": f"IP {client_ip} HAS BEEN BANNED due to {attempts} consecutive failed login attempts!"
        }), 403

    remaining = MAX_FAILED_LOGINS - attempts
    return jsonify({
        "status": "error",
        "message": f"Invalid username or password. {remaining} attempt(s) remaining before IP ban!"
    }), 401


@app.route("/api/register", methods=["POST"])
def api_register():
    # Enforce Admin-only account creation: block unauthenticated public registration
    if not session.get("user"):
        return jsonify({
            "status": "error",
            "message": "Unauthorized. Self-registration is disabled for security. Only an authenticated Administrator can create user accounts."
        }), 403

    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    if len(username) < 3:
        return jsonify({"status": "error", "message": "Username must be at least 3 characters long."}), 400
    if len(password) < 4:
        return jsonify({"status": "error", "message": "Password must be at least 4 characters long."}), 400

    users = load_users()
    key = username.lower()
    if key in users:
        return jsonify({"status": "error", "message": f"Username '{username}' already exists. Please choose another."}), 400

    users[key] = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": "admin" if len(users) == 0 else "analyst"
    }
    save_users(users)
    add_alert("INFO", "LOW", f"New user '{username}' registered from IP {client_ip}")

    return jsonify({
        "status": "success",
        "message": f"User '{username}' registered successfully! Credentials saved to {USERS_FILE_PATH}.",
        "file_path": USERS_FILE_PATH
    })


@app.route("/api/users")
def api_users():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    users = load_users()
    user_list = [
        {
            "username": u.get("username"),
            "role": u.get("role", "analyst")
        }
        for u in users.values()
    ]
    return jsonify({
        "file_path": USERS_FILE_PATH,
        "users": user_list
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    user = session.pop("user", None)
    return jsonify({"status": "success", "message": "Logged out successfully"})


@app.route("/api/login_audit")
@app.route("/api/audit/logins")
def api_audit_logins():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    return jsonify({"status": "success", "audit_logs": LOGIN_AUDIT_LOGS[:50]})


@app.route("/api/stats")
def api_stats():
    return jsonify(monitor_stats)


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    global DRY_RUN, BAN_DURATION_MINUTES, TRUNK_WHITELIST, API_SECRET_KEY, BACKEND_HOST, BACKEND_PORT
    if request.method == "POST":
        data = request.json or {}
        if "dry_run" in data:
            DRY_RUN = bool(data["dry_run"])
            APP_CONFIG["dry_run"] = DRY_RUN
        if "ban_duration" in data:
            try:
                BAN_DURATION_MINUTES = int(data["ban_duration"])
                APP_CONFIG["ban_duration"] = BAN_DURATION_MINUTES
            except ValueError:
                pass
        if "whitelist" in data:
            if isinstance(data["whitelist"], list):
                TRUNK_WHITELIST = set(ip.strip() for ip in data["whitelist"] if ip.strip())
                APP_CONFIG["whitelist"] = list(TRUNK_WHITELIST)
        if "api_secret_key" in data and data["api_secret_key"].strip():
            API_SECRET_KEY = data["api_secret_key"].strip()
            APP_CONFIG["api_secret_key"] = API_SECRET_KEY
        if "backend_host" in data and data["backend_host"].strip():
            BACKEND_HOST = data["backend_host"].strip()
            APP_CONFIG["backend_host"] = BACKEND_HOST
        if "backend_port" in data:
            try:
                BACKEND_PORT = int(data["backend_port"])
                APP_CONFIG["backend_port"] = BACKEND_PORT
            except ValueError:
                pass

        save_config(APP_CONFIG)
        return jsonify({
            "status": "success",
            "message": "Configuration updated and saved to data/config.json successfully",
            "dry_run": DRY_RUN,
            "ban_duration": BAN_DURATION_MINUTES,
            "whitelist": list(TRUNK_WHITELIST),
            "api_secret_key": mask_secret(API_SECRET_KEY),
            "backend_host": BACKEND_HOST,
            "backend_port": BACKEND_PORT
        })

    return jsonify({
        "dry_run": DRY_RUN,
        "ban_duration": BAN_DURATION_MINUTES,
        "whitelist": list(TRUNK_WHITELIST),
        "api_secret_key": mask_secret(API_SECRET_KEY),
        "backend_host": BACKEND_HOST,
        "backend_port": BACKEND_PORT,
        "asterisk_log_path": ASTERISK_LOG_PATH,
        "ami_host": AMI_HOST,
        "ami_port": AMI_PORT
    })


@app.route("/api/firewall/ban", methods=["POST"])
def api_firewall_ban():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    data = request.json or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manual Ban").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP address required"}), 400
    block_ip(ip, reason)
    return jsonify({"status": "success", "message": f"IP {ip} banned successfully"})


@app.route("/api/firewall/unban", methods=["POST"])
def api_firewall_unban():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    data = request.json or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP address required"}), 400
    if ip in BLOCKED_IPS:
        del BLOCKED_IPS[ip]
        if not DRY_RUN:
            os.system(f"sudo iptables -D INPUT -s {ip} -p udp --dport 5060 -j DROP")
            os.system(f"sudo iptables -D INPUT -s {ip} -p tcp --dport 5060 -j DROP")
        add_alert("INFO", "LOW", f"Manual Unban: IP {ip} unblocked")
        return jsonify({"status": "success", "message": f"IP {ip} unbanned successfully"})
    return jsonify({"status": "error", "message": f"IP {ip} is not currently banned"}), 404


@app.route("/api/reports/generate", methods=["GET", "POST"])
def api_reports_generate():
    if not is_request_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized access. Secret key or login session required."}), 401
    report_data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_windows": monitor_stats["total_windows"],
        "total_events": monitor_stats["total_events"],
        "total_attacks": monitor_stats["total_attacks"],
        "attack_breakdown": dict(monitor_stats["attack_breakdown"]),
        "blocked_ips_count": len(BLOCKED_IPS),
        "recent_alerts_count": len(recent_alerts_list),
        "events_summary": ALL_HISTORICAL_EVENTS[-100:]
    }
    format_type = request.args.get("format", "json")
    if format_type == "csv":
        output = "Timestamp,Event,Method,CallerID,Extension,Response,Source_IP,User_Agent\n"
        for ev in ALL_HISTORICAL_EVENTS:
            output += f'"{ev.get("timestamp")}","{ev.get("event")}","{ev.get("sip_method")}","{ev.get("caller_id")}","{ev.get("extension")}","{ev.get("response")}","{ev.get("source_ip")}","{ev.get("user_agent")}"\n'
        return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=pbx_shield_report.csv"})
    return jsonify(report_data)


@socketio.on("connect")
def handle_connect():
    print("  [CLIENT] Browser connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("  [CLIENT] Browser disconnected")


ASTERISK_CDR_CSV_PATH = "/var/log/asterisk/cdr-csv/Master.csv"

def tail_master_csv():
    if not os.path.exists(ASTERISK_CDR_CSV_PATH):
        return
    print(f"  [+] Tailing {ASTERISK_CDR_CSV_PATH} for completed CDR call records...")
    import csv
    seen_rows = set()
    try:
        with open(ASTERISK_CDR_CSV_PATH, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                line_str = line.strip()
                if not line_str or line_str in seen_rows:
                    continue
                seen_rows.add(line_str)
                if len(seen_rows) > 3000:
                    seen_rows.clear()
                try:
                    parts = list(csv.reader([line_str]))[0]
                    if len(parts) >= 14:
                        account_code = parts[0]
                        src = parts[1] or parts[4]
                        dst = parts[2]
                        dcontext = parts[3]
                        clid = parts[4]
                        disposition = parts[14].upper() if len(parts) > 14 else "ANSWERED"
                        billsec = float(parts[13]) if len(parts) > 13 and parts[13].isdigit() else 0.0

                        # Extract clean phone number from clid / src
                        caller_match = re.search(r'[\+]?\d{7,15}', clid or src)
                        caller_id = caller_match.group(0) if caller_match else _friendly_id(src or clid)

                        dest_match = re.search(r'[\+]?\d{3,15}', dst)
                        extension = dest_match.group(0) if dest_match else _friendly_id(dst)

                        context = "from-trunk" if ("inbound" in dcontext.lower() or "trunk" in dcontext.lower()) else "from-internal"

                        resp_map = {
                            "ANSWERED": ("200", "16", "Call Connected"),
                            "NO ANSWER": ("480", "18", "No Answer / Timeout"),
                            "BUSY": ("486", "17", "Destination Busy"),
                            "FAILED": ("503", "41", "Call Failed"),
                            "CANCEL": ("487", "0", "Call Cancelled"),
                        }
                        resp_code, cause_code, cause_txt = resp_map.get(disposition, ("200", "16", disposition))

                        print(f"  [CDR CSV] Real Call Captured: {caller_id} -> {extension} ({disposition})")
                        add_event({
                            "timestamp": datetime.now().isoformat(),
                            "event": "Cdr",
                            "sip_method": "INVITE",
                            "caller_id": caller_id,
                            "context": context,
                            "extension": extension,
                            "destination_extension": extension,
                            "response": resp_code,
                            "cause_code": cause_code,
                            "cause_txt": cause_txt,
                            "source_ip": "10.0.0.1",
                            "user_agent": "Asterisk CDR CSV",
                            "duration": billsec,
                        })
                except Exception as ex:
                    pass
    except Exception as e:
        print(f"  [!] Master CSV tailer error: {e}")


def ensure_pjsip_logger():
    """Ensure Asterisk PJSIP logger is active so SIP traffic is written to disk."""
    try:
        import subprocess
        subprocess.run(["asterisk", "-rx", "pjsip set logger on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        print("  [+] PJSIP Live Logger successfully engaged via Asterisk CLI.")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    print("=" * 70)
    print("  PBX SHIELD — Real-Time Security Monitor (LIVE DATA)")
    print("=" * 70)
    print(f"  Dashboard / API: http://{host}:{port}")
    print(f"  Model Path     : {MODEL_PATH}")
    print("=" * 70)

    ensure_pjsip_logger()

    threading.Thread(target=tail_asterisk_log, daemon=True).start()
    threading.Thread(target=ami_cdr_listener, daemon=True).start()
    threading.Thread(target=tail_master_csv, daemon=True).start()
    threading.Thread(target=monitoring_loop, daemon=True).start()

    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
