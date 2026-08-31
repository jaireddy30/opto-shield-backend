# 🛡️ PBX SHIELD — BACKEND TELEMETRY & AI FIREWALL ENGINE

PBX Shield Backend is a real-time security monitoring and automated firewall defense system for **Asterisk VoIP/SIP PBX infrastructure**. It processes raw Asterisk AMI events, `/var/log/asterisk/full` logs, and CDR records (`Master.csv`), classifies traffic every 60 seconds using a **LightGBM Machine Learning Model**, and auto-bans malicious IPs via `iptables`.

---

## 🚀 Quick Start & Deployment

### 1. Requirements
* Linux (Ubuntu 20.04/22.04/24.04 recommended) with Asterisk PBX installed.
* Python 3.10+
* `sudo` privileges for `iptables` firewall execution.

### 2. Environment Setup
```bash
git clone https://github.com/jaireddy30/PBX_ml_backend.git
cd PBX_ml_backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Launching the Backend Server
```bash
python3 src/monitor.py
```
> The backend server listens on **`0.0.0.0:5000`** and streams live WebSocket threat telemetry to connected SOC frontends.

---

## 🔑 Security & Configuration (`data/config.json`)

The backend automatically creates `data/config.json` on initial boot:

```json
{
  "backend_host": "0.0.0.0",
  "backend_port": 5000,
  "api_secret_key": "5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78",
  "dry_run": true,
  "ban_duration": 10,
  "whitelist": []
}
```

* **`X-API-Key` Authentication**: All REST API endpoints require the `X-API-Key` header matching `api_secret_key`.
* **`dry_run: true`**: Monitors and classifies threats without executing live `iptables` DROP commands. Set to `false` in production for automatic firewall blocking.

---

## 📡 REST API Reference

| Route | Method | Header Required | Description |
| :--- | :---: | :---: | :--- |
| `/api/login` | `POST` | None | Authenticate admin session. Auto-bans client IP on 3 failed attempts. |
| `/api/stats` | `GET` | `X-API-Key` / Session | Return current classification stats & attack counter. |
| `/api/settings` | `GET` / `POST` | `X-API-Key` / Session | Read or update configuration (Secret key is redacted as `••••••••ce78`). |
| `/api/users` | `GET` | `X-API-Key` / Session | List authorized user accounts. |
| `/api/audit/logins` | `GET` | `X-API-Key` / Session | View detailed login security audit log. |
| `/api/firewall/ban` | `POST` | `X-API-Key` / Session | Manually ban an IP address (`{"ip": "1.2.3.4", "reason": "Admin Ban"}`). |
| `/api/firewall/unban` | `POST` | `X-API-Key` / Session | Unban a blocked IP address. |
| `/api/reports/generate`| `GET` / `POST` | `X-API-Key` / Session | Export full CDR security audit reports in JSON or CSV. |

---

## 🤖 AI Threat Classification Matrix

The LightGBM Machine Learning engine processes 11 real-time sliding-window features to classify threats into 7 security categories:
1. **`NORMAL`**: Legitimate business SIP traffic.
2. **`INVITE_FLOOD`**: High-density burst of SIP `INVITE` packets attempting channel exhaustion.
3. **`SIP_SCANNER`**: Automated user-agent probes.
4. **`REGISTER_BRUTE_FORCE`**: Repeated registration password cracking attempts.
5. **`EXTENSION_ENUMERATION`**: Probing sequential extension ranges (`1000`-`1999`).
6. **`OPTIONS_FLOOD`**: Continuous `OPTIONS` keep-alive packet flooding.
7. **`TOLL_FRAUD`**: Unauthorized international or premium-rate dialing patterns.

---

## 📑 Security Audit Reports Included
* [`PBX_SHIELD_SECURITY_AUDIT_REPORT.md`](PBX_SHIELD_SECURITY_AUDIT_REPORT.md)
* [`PBX_SHIELD_PENETRATION_ATTACK_REPORT.md`](PBX_SHIELD_PENETRATION_ATTACK_REPORT.md)
* [`PBX_SHIELD_PENETRATION_ATTACK_REPORT.docx`](PBX_SHIELD_PENETRATION_ATTACK_REPORT.docx)
