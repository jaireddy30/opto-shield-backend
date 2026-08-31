# 🛡️ PBX SHIELD — STANDALONE FRONTEND SOC CONSOLE

A modern, responsive, standalone Security Operations Center (SOC) dashboard for monitoring real-time SIP traffic and AI threat telemetry across **multiple Asterisk PBX servers**.

---

## ⚙️ Configuration (`.env`)

The frontend application uses a `.env` file for configuration. Copy `.env.example` to `.env` and adjust the variables:

```env
# Frontend Server Host & Port (0.0.0.0 listens on all interfaces)
HOST=0.0.0.0
PORT=9000

# Default PBX Shield Asterisk Backend Target
DEFAULT_BACKEND_HOST=13.126.90.199
DEFAULT_BACKEND_PORT=5000
DEFAULT_API_KEY=5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78
```

---

## 🚀 Running the Frontend Server

You can run the frontend server using **Node.js** or **Python**:

### Option 1: Node.js
```bash
npm install
npm start
```

### Option 2: Python
```bash
python server.py
```

* The frontend listens on **`http://0.0.0.0:9000`** (accessible at `http://<YOUR_SERVER_IP>:9000`).

---

## 🖥️ Multi-Backend Server Management

The SOC dashboard supports connecting to and switching between **multiple Asterisk PBX servers** running PBX Shield:
1. **Server Selector Dropdown**: Located in the sidebar to switch live telemetry streams between configured Asterisk servers.
2. **Add New Server**: Click **"+ Add New PBX Server"** in the sidebar or Managed Servers tab to add new PBX Shield backends (Name, IP/Host, Port, API Secret Key).
3. **Persistent Storage**: Saved servers are retained in your browser's local storage.
