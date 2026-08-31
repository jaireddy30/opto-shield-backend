import json
import random
import os

random.seed(42)

OUTPUT_FILE = "data/processed/training_data.json"

# Change these numbers later to reach 200000
CLASS_COUNTS = {
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


def rint(a, b):
    return random.randint(a, b)


def rfloat(a, b):
    return round(random.uniform(a, b), 2)


dataset = []


def add_normal():

    return {

        "invite_count_60s": rint(1, 8),

        "register_count_60s": rint(0, 3),

        "options_count_60s": rint(0, 3),

        "failed_count_60s": rint(0, 2),

        "unique_callers_60s": rint(1, 5),

        "unique_extensions_60s": rint(1, 4),

        "unknown_caller_ratio": rfloat(0.00, 0.05),

        "request_rate": rfloat(0.05, 0.30),

        "failure_ratio": rfloat(0.00, 0.08),

        "avg_call_duration": rint(60, 600),

        "short_call_ratio": rfloat(0.00, 0.10),

        "label": LABELS["NORMAL"]
    }


def add_invite():

    return {

        "invite_count_60s": rint(80, 250),

        "register_count_60s": rint(0, 2),

        "options_count_60s": rint(0, 20),

        "failed_count_60s": rint(70, 240),

        "unique_callers_60s": rint(20, 60),

        "unique_extensions_60s": rint(30, 80),

        "unknown_caller_ratio": rfloat(0.60, 1.00),

        "request_rate": rfloat(1.0, 5.0),

        "failure_ratio": rfloat(0.75, 1.00),

        "avg_call_duration": rint(0, 5),

        "short_call_ratio": rfloat(0.80, 1.00),

        "label": LABELS["INVITE_FLOOD"]
    }


def add_scanner():

    return {

        "invite_count_60s": rint(10, 50),

        "register_count_60s": rint(0, 3),

        "options_count_60s": rint(20, 120),

        "failed_count_60s": rint(10, 60),

        "unique_callers_60s": rint(20, 70),

        "unique_extensions_60s": rint(30, 200),

        "unknown_caller_ratio": rfloat(0.40, 0.90),

        "request_rate": rfloat(0.5, 3.0),

        "failure_ratio": rfloat(0.50, 0.90),

        "avg_call_duration": rint(0, 8),

        "short_call_ratio": rfloat(0.60, 1.00),

        "label": LABELS["SIP_SCANNER"]
    }


def add_register():

    return {

        "invite_count_60s": rint(0, 5),

        "register_count_60s": rint(100, 400),

        "options_count_60s": rint(0, 10),

        "failed_count_60s": rint(90, 390),

        "unique_callers_60s": rint(1, 15),

        "unique_extensions_60s": rint(5, 30),

        "unknown_caller_ratio": rfloat(0.20, 0.80),

        "request_rate": rfloat(1.0, 4.0),

        "failure_ratio": rfloat(0.80, 1.00),

        "avg_call_duration": 0,

        "short_call_ratio": 1.0,

        "label": LABELS["REGISTER_BRUTE_FORCE"]
    }


def add_enum():

    return {

        "invite_count_60s": rint(30, 120),

        "register_count_60s": rint(0, 2),

        "options_count_60s": rint(0, 10),

        "failed_count_60s": rint(20, 100),

        "unique_callers_60s": rint(5, 20),

        "unique_extensions_60s": rint(80, 300),

        "unknown_caller_ratio": rfloat(0.40, 0.90),

        "request_rate": rfloat(0.5, 3.0),

        "failure_ratio": rfloat(0.50, 0.95),

        "avg_call_duration": rint(0, 5),

        "short_call_ratio": rfloat(0.60, 1.00),

        "label": LABELS["EXTENSION_ENUMERATION"]
    }


def add_options():

    return {

        "invite_count_60s": rint(0, 10),

        "register_count_60s": rint(0, 5),

        "options_count_60s": rint(100, 500),

        "failed_count_60s": rint(0, 20),

        "unique_callers_60s": rint(30, 90),

        "unique_extensions_60s": rint(10, 40),

        "unknown_caller_ratio": rfloat(0.20, 0.90),

        "request_rate": rfloat(2.0, 6.0),

        "failure_ratio": rfloat(0.00, 0.20),

        "avg_call_duration": 0,

        "short_call_ratio": 1.0,

        "label": LABELS["OPTIONS_FLOOD"]
    }


def add_toll():

    return {

        "invite_count_60s": rint(20, 80),

        "register_count_60s": rint(1, 5),

        "options_count_60s": rint(0, 5),

        "failed_count_60s": rint(0, 5),

        "unique_callers_60s": rint(1, 5),

        "unique_extensions_60s": rint(20, 80),

        "unknown_caller_ratio": rfloat(0.00, 0.10),

        "request_rate": rfloat(0.30, 1.00),

        "failure_ratio": rfloat(0.00, 0.05),

        "avg_call_duration": rint(300, 3600),

        "short_call_ratio": rfloat(0.00, 0.10),

        "label": LABELS["TOLL_FRAUD"]
    }


GENERATORS = {
    "NORMAL": add_normal,
    "INVITE_FLOOD": add_invite,
    "SIP_SCANNER": add_scanner,
    "REGISTER_BRUTE_FORCE": add_register,
    "EXTENSION_ENUMERATION": add_enum,
    "OPTIONS_FLOOD": add_options,
    "TOLL_FRAUD": add_toll
}


for attack_type, count in CLASS_COUNTS.items():

    print(f"Generating {attack_type}: {count}")

    generator = GENERATORS[attack_type]

    for _ in range(count):
        dataset.append(generator())


random.shuffle(dataset)

os.makedirs("data/processed", exist_ok=True)

with open(OUTPUT_FILE, "w") as f:
    json.dump(dataset, f, indent=4)

print("\n===================================")
print("Dataset generated successfully")
print("Records :", len(dataset))
print("Saved to:", OUTPUT_FILE)
print("===================================")