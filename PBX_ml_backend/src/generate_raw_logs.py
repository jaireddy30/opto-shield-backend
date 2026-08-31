import json
import os
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

RAW_LOG_FILE = "data/raw/raw_logs.json"
WINDOW_LABELS_FILE = "data/raw/window_labels.json"

WINDOW_COUNTS = {
    "NORMAL": 12000,
    "INVITE_FLOOD": 2500,
    "SIP_SCANNER": 2000,
    "REGISTER_BRUTE_FORCE": 1500,
    "EXTENSION_ENUMERATION": 1000,
    "OPTIONS_FLOOD": 500,
    "TOLL_FRAUD": 500
}

LABELS = {
    "NORMAL": 0,
    "INVITE_FLOOD": 1,
    "SIP_SCANNER": 2,
    "REGISTER_BRUTE_FORCE": 3,
    "EXTENSION_ENUMERATION": 4,
    "OPTIONS_FLOOD": 5,
    "TOLL_FRAUD": 6
}

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


def make_event(window_id, ts, sip_method, source_ip, caller_id, extension, response, duration, context=None, user_agent=None, event=None):
    cause_code, cause_txt = RESPONSE_CAUSE_MAP.get(str(response), ("0", "Unknown Cause"))
    
    is_internal = source_ip.startswith("192.168.")
    
    if not context:
        context = "from-internal" if is_internal else "from-trunk"
        
    if not user_agent:
        if is_internal:
            user_agent = "Asterisk PBX 18.16.0"
        else:
            user_agent = random.choice(["sipvicious", "friendly-scanner", "Zoiper v5.5", "pp-sip-tool", "MicroSIP 3.20.7"])
            
    if not event:
        if sip_method in ["REGISTER", "OPTIONS"]:
            event = "SIP_REQUEST"
        else:
            event = "Cdr" if response == "200" else "Newchannel"

    return {
        "window_id": window_id,
        "timestamp": ts.isoformat(),
        "event": event,
        "sip_method": sip_method,
        "caller_id": caller_id,
        "context": context,
        "extension": extension,
        "destination_extension": extension,
        "response": response,
        "cause": cause_code,
        "cause_code": cause_code,
        "cause_txt": cause_txt,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "duration": duration
    }


def add_background_noise(events, window_id, t0, chance=0.15):
    if random.random() > chance:
        return
    ip = fake_internal_ip()
    for _ in range(rint(1, 4)):
        caller = random.choice(KNOWN_CALLERS)
        ext = random.choice(KNOWN_EXTENSIONS)
        answered = random.random() > 0.1
        response = "200" if answered else random.choice(FAIL_CODES_CALL)
        duration = rint(20, 400) if answered else 0
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, caller, ext, response, duration))


def gen_normal(window_id, t0):
    events = []
    ip = fake_internal_ip()
    busy = random.random() < 0.08
    n_calls = rint(8, 18) if busy else rint(1, 8)

    for _ in range(n_calls):
        caller = random.choice(KNOWN_CALLERS)
        ext = random.choice(KNOWN_EXTENSIONS)
        answered = random.random() > (0.15 if busy else 0.08)
        response = "200" if answered else random.choice(FAIL_CODES_CALL + FAIL_CODES_SERVER)
        duration = rint(15, 600) if answered else 0
        ts = t0 + timedelta(seconds=rint(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, caller, ext, response, duration))

    for _ in range(rint(0, 4)):
        caller = random.choice(KNOWN_CALLERS)
        ext = random.choice(KNOWN_EXTENSIONS)
        response = "200" if random.random() > 0.03 else random.choice(FAIL_CODES_AUTH)
        ts = t0 + timedelta(seconds=rint(0, 59))
        events.append(make_event(window_id, ts, "REGISTER", ip, caller, ext, response, 0))

    for _ in range(rint(0, 5)):
        ts = t0 + timedelta(seconds=rint(0, 59))
        events.append(make_event(window_id, ts, "OPTIONS", ip, "Unknown", random.choice(KNOWN_EXTENSIONS), "200", 0))

    return events


def gen_invite_flood(window_id, t0):
    events = []
    ip = fake_external_ip()
    stealthy = random.random() < 0.2
    n = rint(15, 45) if stealthy else rint(60, 260)
    fail_rate = random.uniform(0.55, 0.98)

    for _ in range(n):
        ext = random.choice(ALL_EXTENSIONS)
        fail = random.random() < fail_rate
        response = random.choice(FAIL_CODES_NOTFOUND + FAIL_CODES_CALL + FAIL_CODES_SERVER) if fail else "200"
        duration = 0 if fail else rint(0, 8)
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, "Unknown", ext, response, duration))

    add_background_noise(events, window_id, t0, chance=0.2)
    return events


def gen_sip_scanner(window_id, t0):
    events = []
    ip = fake_external_ip()
    stealthy = random.random() < 0.25
    n_opt = rint(8, 35) if stealthy else rint(25, 130)

    targets = [random.choice(ALL_EXTENSIONS) for _ in range(n_opt)]
    for ext in targets:
        response = "200" if ext in KNOWN_EXTENSIONS else "404"
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "OPTIONS", ip, "Unknown", ext, response, 0))

    for _ in range(rint(5, 55)):
        ext = random.choice(ALL_EXTENSIONS)
        response = "200" if ext in KNOWN_EXTENSIONS else "404"
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, "Unknown", ext, response, 0))

    add_background_noise(events, window_id, t0, chance=0.15)
    return events


def gen_register_brute_force(window_id, t0):
    events = []
    ip = fake_external_ip()
    target_ext = random.choice(KNOWN_EXTENSIONS)
    stealthy = random.random() < 0.2
    n = rint(40, 90) if stealthy else rint(90, 420)
    crack_chance = random.uniform(0.0, 0.03)

    for _ in range(n):
        cracked = random.random() < crack_chance
        response = "200" if cracked else random.choice(FAIL_CODES_AUTH)
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "REGISTER", ip, "Unknown", target_ext, response, 0))

    add_background_noise(events, window_id, t0, chance=0.1)
    return events


def gen_extension_enumeration(window_id, t0):
    events = []
    ip = fake_external_ip()
    stealthy = random.random() < 0.25
    n = rint(15, 40) if stealthy else rint(40, 130)

    targets = random.sample(ALL_EXTENSIONS, min(n, len(ALL_EXTENSIONS)))
    for ext in targets:
        response = "200" if ext in KNOWN_EXTENSIONS else "404"
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, "Unknown", ext, response, 0))

    add_background_noise(events, window_id, t0, chance=0.15)
    return events


def gen_options_flood(window_id, t0):
    events = []
    ip = fake_external_ip()
    n = rint(60, 520)
    fail_rate = random.uniform(0.0, 0.15)

    for _ in range(n):
        ext = random.choice(KNOWN_EXTENSIONS + ALL_EXTENSIONS[:80])
        fail = random.random() < fail_rate
        response = random.choice(FAIL_CODES_SERVER) if fail else "200"
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "OPTIONS", ip, "Unknown", ext, response, 0))

    add_background_noise(events, window_id, t0, chance=0.2)
    return events


def gen_toll_fraud(window_id, t0):
    events = []
    ip = fake_internal_ip()
    compromised_ext = random.choice(KNOWN_EXTENSIONS)
    caller = random.choice(KNOWN_CALLERS)
    cautious = random.random() < 0.3
    n = rint(5, 20) if cautious else rint(20, 90)

    for _ in range(n):
        dest = random.choice(TOLL_DESTINATIONS)
        answered = random.random() > 0.06
        response = "200" if answered else random.choice(FAIL_CODES_CALL)
        duration = rint(60, 3600) if answered else 0
        ts = t0 + timedelta(seconds=random.uniform(0, 59))
        events.append(make_event(window_id, ts, "INVITE", ip, caller, compromised_ext + "->" + dest, response, duration))

    add_background_noise(events, window_id, t0, chance=0.1)
    return events


GENERATORS = {
    "NORMAL": gen_normal,
    "INVITE_FLOOD": gen_invite_flood,
    "SIP_SCANNER": gen_sip_scanner,
    "REGISTER_BRUTE_FORCE": gen_register_brute_force,
    "EXTENSION_ENUMERATION": gen_extension_enumeration,
    "OPTIONS_FLOOD": gen_options_flood,
    "TOLL_FRAUD": gen_toll_fraud
}


def save_events_json(events, filepath):
    tmp_filepath = filepath + ".tmp"
    total = len(events)
    chunk_size = 100000
    print(f"\nSaving {total:,} events to {filepath}...")
    with open(tmp_filepath, "w", encoding="utf-8") as f:
        f.write("[\n")
        for i in range(0, total, chunk_size):
            chunk = events[i:i + chunk_size]
            chunk_str = ",\n".join(json.dumps(e) for e in chunk)
            if i > 0:
                f.write(",\n")
            f.write(chunk_str)
            pct = min(100, int((i + len(chunk)) / total * 100))
            print(f"  [Progress] {pct}% saved ({min(i + len(chunk), total):,}/{total:,} events)")
        f.write("\n]")
    if os.path.exists(filepath):
        os.remove(filepath)
    os.rename(tmp_filepath, filepath)


def main():
    print("=" * 80)
    print(" PBX RAW LOG GENERATOR (SIMULATED ASTERISK/AMI EVENTS)")
    print("=" * 80)

    all_events = []
    window_labels = {}
    current_time = datetime(2026, 8, 1, 0, 0, 0)

    windows = []
    for attack_type, count in WINDOW_COUNTS.items():
        for _ in range(count):
            windows.append(attack_type)

    random.shuffle(windows)

    for attack_type in windows:
        window_id = str(uuid.uuid4())
        window_labels[window_id] = LABELS[attack_type]

        events = GENERATORS[attack_type](window_id, current_time)
        all_events.extend(events)

        current_time += timedelta(seconds=70)

    total_windows = len(windows)
    print(f"\nGenerated {total_windows} windows across {len(WINDOW_COUNTS)} classes")
    print(f"Total raw SIP events: {len(all_events):,}")
    for attack_type, count in WINDOW_COUNTS.items():
        print(f"  {attack_type:<22}: {count:,} windows")

    os.makedirs("data/raw", exist_ok=True)

    save_events_json(all_events, RAW_LOG_FILE)

    with open(WINDOW_LABELS_FILE, "w", encoding="utf-8") as f:
        json.dump(window_labels, f, indent=2)

    print("\n" + "=" * 80)
    print("RAW LOGS SAVED SUCCESSFULLY")
    print("=" * 80)
    print(f"Events file : {RAW_LOG_FILE}")
    print(f"Labels file : {WINDOW_LABELS_FILE}")

    print("\n" + "=" * 80)
    print("SAMPLE RAW EVENT SCHEMA SHOWING REQUIRED FIELDS")
    print("=" * 80)
    print(json.dumps(all_events[0], indent=2))

if __name__ == "__main__":
    main()
