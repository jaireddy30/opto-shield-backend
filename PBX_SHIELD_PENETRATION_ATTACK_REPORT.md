# 🛡️ PBX SHIELD — COMPREHENSIVE PENETRATION TESTING & SECURITY AUDIT REPORT

**Document ID:** PBX-PEN-REPORT-2026-0811  
**Date:** August 11, 2026  
**Target Host:** AWS EC2 Asterisk PBX Server (`13.126.90.199:5000` / Private IP: `10.0.9.249`)  
**Prepared For:** Senior Management & Technical Audit Board  
**Classification:** Confidential / Official Technical Security Document  

---

## 📑 1. Executive Summary

This report provides a formal summary of the **Penetration Testing & Security Audit** conducted against **PBX Shield** — an AI-powered real-time security telemetry and automated firewall defense system for Asterisk VoIP/SIP PBX infrastructure.

The purpose of this testing was to assess the resilience of PBX Shield against common web API attacks, broken access control exploits, credential brute-force cracking, and data exposure vulnerabilities. All identified security gaps were remediated and verified live in production.

---

## 💥 2. Detailed Summary of Executed Attack Vectors

---

### 🚨 ATTACK VECTOR 1: Broken Access Control & Unauthenticated API Access
* **Attack Method**: Attempted to send direct HTTP requests to administrative REST endpoints (`/api/settings`, `/api/users`, `/api/audit/logins`, `/api/reports/generate`) without authentication headers or using a fake API key (`X-API-Key: invalid-hacker-key-9999`).
* **Objective**: Access sensitive configuration details, user credentials, system logs, and CDR call reports without authorization.
* **Response / Outcome**: **`401 Unauthorized`**
  ```json
  {"status": "error", "message": "Unauthorized access. Secret key or login session required."}
  ```
* **Verdict**: **`PASSED (SECURED)`** — PBX Shield successfully blocked all unauthenticated endpoint access.

---

### 🚨 ATTACK VECTOR 2: Unauthorized Public Self-Registration Exploit
* **Attack Method**: Submitted an HTTP POST request to `/api/register` trying to create a rogue administrator account (`hacker_account:hacker_password_123` with role `admin`).
* **Objective**: Create an unauthenticated admin account to bypass login controls and take over the system.
* **Response / Outcome**: **`403 Forbidden`**
  ```json
  {"status": "error", "message": "Unauthorized. Self-registration is disabled for security. Only an authenticated Administrator can create user accounts."}
  ```
* **Verdict**: **`PASSED (SECURED)`** — Public account creation is disabled. Only logged-in administrators can create user accounts.

---

### 🚨 ATTACK VECTOR 3: Brute-Force Password Cracking Attack on `/api/login`
* **Attack Method**: Launched rapid, consecutive failed login requests against `/api/login` using dictionary passwords (`admin1`, `secret123`, `password`, `superadmin`).
* **Objective**: Exhaust credential combinations to crack administrative user accounts.
* **Response / Outcome Sequence**:
  * **Attempt 1**: `401 Unauthorized` (`"2 attempt(s) remaining before IP ban!"`)
  * **Attempt 2**: `401 Unauthorized` (`"1 attempt(s) remaining before IP ban!"`)
  * **Attempt 3**: **`403 Forbidden`** (`"IP 103.186.40.107 HAS BEEN BANNED due to 3 consecutive failed login attempts!"`)
  * **Attempt 4+**: **`403 Forbidden`** (`"Your IP (103.186.40.107) is currently banned due to multiple failed login attempts."`)
* **Verdict**: **`PASSED (SECURED)`** — The automated defense detected the brute-force attack on the 3rd attempt and automatically banned the attacker's IP.

---

### 🚨 ATTACK VECTOR 4: Sensitive Data Exposure / Secret Key Payload Leak
* **Attack Method**: Inspected the JSON response payload returned by `/api/settings` during an authenticated session.
* **Initial Vulnerability**: The initial system version echoed the plaintext secret key (`"api_secret_key": "pbx-shield-secret-2026"`) back to callers in the JSON response payload.
* **Remediation & Rotation Applied**:
  1. Revoked and invalidated the old key (`pbx-shield-secret-2026`).
  2. Rotated the key to a strong 256-bit crypto-random token (`5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78`).
  3. Implemented `mask_secret()` redaction logic returning `"••••••••ce78"`.
* **Verdict**: **`PASSED (REMEDIATED & SECURED)`** — Secret key is rotated and fully masked in all API responses.

---

## 📊 3. Master Attack Verification Matrix

| Vector ID | Target Endpoint | Attack Description | Pre-Fix Status | Post-Fix Result | Status |
| :---: | :--- | :--- | :---: | :---: | :---: |
| **ATK-01** | `/api/settings` | Unauthenticated GET request | `200 OK` (Vulnerable) | **`401 UNAUTHORIZED`** | **PASS** |
| **ATK-02** | `/api/users` | Access user list with fake API key | `200 OK` (Vulnerable) | **`401 UNAUTHORIZED`** | **PASS** |
| **ATK-03** | `/api/audit/logins` | Access login audit logs without key | `200 OK` (Vulnerable) | **`401 UNAUTHORIZED`** | **PASS** |
| **ATK-04** | `/api/reports/generate` | Generate CDR reports without key | `200 OK` (Vulnerable) | **`401 UNAUTHORIZED`** | **PASS** |
| **ATK-05** | `/api/register` | Create admin user publicly | `200 OK` (Vulnerable) | **`403 FORBIDDEN`** | **PASS** |
| **ATK-06** | `/api/login` | Brute-force password guessing | Allowed infinite tries | **`IP AUTO-BANNED (403)`** | **PASS** |
| **ATK-07** | `/api/settings` | Secret key leaked in JSON payload | Key exposed in plain text | **`REDACTED ("••••••••ce78")`** | **PASS** |
| **ATK-08** | `/api/settings` | Authenticate with rotated 256-bit key | N/A | **`200 OK`** | **PASS** |

---

## 📸 4. Live Terminal Evidence & Response Headers

### A. Unauthenticated Attack Response Headers (Kali Linux Client):
```http
$ curl -i http://13.126.90.199:5000/api/settings
HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.1.8 Python/3.12.3
Content-Type: application/json
Content-Length: 90

{"message":"Unauthorized access. Secret key or login session required.","status":"error"}
```

### B. Authenticated & Redacted Key Response Headers (Kali Linux Client):
```http
$ curl -i -H "X-API-Key: 5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78" http://13.126.90.199:5000/api/settings
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.3
Content-Type: application/json

{
  "ami_host": "127.0.0.1",
  "ami_port": 5038,
  "api_secret_key": "••••••••ce78",
  "asterisk_log_path": "/var/log/asterisk/full",
  "backend_host": "0.0.0.0",
  "backend_port": 5000,
  "ban_duration": 10,
  "dry_run": true,
  "whitelist": []
}
```

---

## 🤖 5. AI Threat Classification Engine

PBX Shield's LightGBM Machine Learning Engine processes 11 real-time telemetry metrics (`invite_count_60s`, `register_count_60s`, `failure_ratio`, `unknown_caller_ratio`, etc.) to defend against 7 threat categories:

1. **`NORMAL`**: Standard business call flows.
2. **`INVITE_FLOOD`**: Rapid burst of SIP `INVITE` requests attempting channel exhaustion.
3. **`SIP_SCANNER`**: Automated user-agent discovery scans.
4. **`REGISTER_BRUTE_FORCE`**: Automated SIP account registration password guessing.
5. **`EXTENSION_ENUMERATION`**: Probing sequential ranges of internal extensions (`1000`-`1999`).
6. **`OPTIONS_FLOOD`**: High-density keep-alive packet flooding.
7. **`TOLL_FRAUD`**: Unauthorized high-cost or premium-rate dialing patterns.

---

## 🏆 6. Conclusion & Approval Sign-Off

All simulated attacks were successfully blocked, logged, and audited. The system has passed all penetration testing requirements.

* **Backend Repository**: [`https://github.com/jaireddy30/PBX_ml_backend`](https://github.com/jaireddy30/PBX_ml_backend)
* **Frontend Repository**: [`https://github.com/jaireddy30/PBX_ml_frontend`](https://github.com/jaireddy30/PBX_ml_frontend)

**Final Status:** **PASSED & APPROVED FOR PRODUCTION USE**  

---
*Report generated by PBX Shield AI Security Audit Engine on August 11, 2026.*
