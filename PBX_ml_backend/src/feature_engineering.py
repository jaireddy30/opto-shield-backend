import json
import os
import pandas as pd

RAW_LOG_FILE = "data/raw/raw_logs.json"
WINDOW_LABELS_FILE = "data/raw/window_labels.json"
OUTPUT_FILE = "data/processed/training_data.json"

SUCCESS_CODES = {"200"}
SHORT_CALL_THRESHOLD_SECONDS = 5

FEATURE_COLUMNS = [
    "invite_count_60s",
    "register_count_60s",
    "options_count_60s",
    "failed_count_60s",
    "unique_callers_60s",
    "unique_extensions_60s",
    "unknown_caller_ratio",
    "request_rate",
    "failure_ratio",
    "avg_call_duration",
    "short_call_ratio"
]


def compute_window_features(events):
    """Turn a list of raw SIP events (one 60-second window) into
    the 11 numerical features the LightGBM model trains on."""

    total = len(events)

    invite_events = [e for e in events if e["sip_method"] == "INVITE"]
    register_events = [e for e in events if e["sip_method"] == "REGISTER"]
    options_events = [e for e in events if e["sip_method"] == "OPTIONS"]

    invite_count_60s = len(invite_events)
    register_count_60s = len(register_events)
    options_count_60s = len(options_events)

    failed_count_60s = sum(1 for e in events if e["response"] not in SUCCESS_CODES)

    callers = [e["caller_id"] for e in events]
    unique_callers_60s = len(set(callers))

    extensions = [e["destination_extension"] for e in events]
    unique_extensions_60s = len(set(extensions))

    unknown_caller_ratio = (
        sum(1 for c in callers if c == "Unknown") / total if total > 0 else 0.0
    )

    request_rate = total / 60.0

    failure_ratio = failed_count_60s / total if total > 0 else 0.0

    successful_invites = [e for e in invite_events if e["response"] in SUCCESS_CODES]
    if successful_invites:
        avg_call_duration = sum(e["duration"] for e in successful_invites) / len(successful_invites)
    else:
        avg_call_duration = 0.0

    if invite_count_60s > 0:
        short_calls = sum(1 for e in invite_events if e["duration"] < SHORT_CALL_THRESHOLD_SECONDS)
        short_call_ratio = short_calls / invite_count_60s
    else:
        short_call_ratio = 0.0

    return {
        "invite_count_60s": invite_count_60s,
        "register_count_60s": register_count_60s,
        "options_count_60s": options_count_60s,
        "failed_count_60s": failed_count_60s,
        "unique_callers_60s": unique_callers_60s,
        "unique_extensions_60s": unique_extensions_60s,
        "unknown_caller_ratio": round(unknown_caller_ratio, 4),
        "request_rate": round(request_rate, 4),
        "failure_ratio": round(failure_ratio, 4),
        "avg_call_duration": round(avg_call_duration, 2),
        "short_call_ratio": round(short_call_ratio, 4)
    }


def main():
    print("=" * 80)
    print("           PBX FEATURE ENGINEERING (RAW LOGS -> TRAINING DATA)")
    print("=" * 80)

    if not os.path.exists(RAW_LOG_FILE):
        print(f"\nERROR : Raw log file not found at {RAW_LOG_FILE}")
        print("Run src/generate_raw_logs.py first.")
        return

    if not os.path.exists(WINDOW_LABELS_FILE):
        print(f"\nERROR : Window labels file not found at {WINDOW_LABELS_FILE}")
        print("Run src/generate_raw_logs.py first.")
        return

    with open(RAW_LOG_FILE, encoding="utf-8") as f:
        events = json.load(f)

    with open(WINDOW_LABELS_FILE, encoding="utf-8") as f:
        window_labels = json.load(f)

    print(f"\nLoaded {len(events)} raw SIP events")
    print(f"Loaded {len(window_labels)} labeled windows")

    # --------------------------------------------------------
    # GROUP EVENTS BY WINDOW
    # --------------------------------------------------------

    df = pd.DataFrame(events)
    grouped = df.groupby("window_id")

    print("\nComputing features for each 60-second window...")

    rows = []
    missing_labels = 0

    for window_id, group in grouped:
        if window_id not in window_labels:
            missing_labels += 1
            continue

        window_events = group.to_dict("records")
        features = compute_window_features(window_events)
        features["label"] = window_labels[window_id]
        rows.append(features)

    if missing_labels:
        print(f"WARNING: {missing_labels} windows had no matching label and were skipped")

    result_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])

    print(f"\nBuilt {len(result_df)} training rows")
    print("\nClass Distribution\n")
    print(result_df["label"].value_counts().sort_index())

    os.makedirs("data/processed", exist_ok=True)

    result_df.to_json(OUTPUT_FILE, orient="records", indent=4)

    print("\n" + "=" * 80)
    print("FEATURE ENGINEERING COMPLETE")
    print("=" * 80)
    print(f"Saved to: {OUTPUT_FILE}")
    print("\nThis file has the exact same shape as before, so train.py")
    print("needs NO changes and will work as-is.")


if __name__ == "__main__":
    main()