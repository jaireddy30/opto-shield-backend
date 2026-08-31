import http.server
import socketserver
import os
import json
import base64
import time
import sqlite3

def load_env():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")

load_env()

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 9000))
FRONTEND_ADMIN_USER = os.getenv("FRONTEND_ADMIN_USER", "admin")
FRONTEND_ADMIN_PASS = os.getenv("FRONTEND_ADMIN_PASS", "admin123")
DEFAULT_BACKEND_HOST = "13.126.90.199"
DEFAULT_BACKEND_PORT = "5000"
DEFAULT_API_KEY = "5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78"

# ---------------------------------------------------------------------------
# Frontend SQLite Database (frontend.db)
# ---------------------------------------------------------------------------
FRONTEND_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend.db")

def init_frontend_db():
    """Initialize persistent SQLite database for frontend profiles and settings."""
    conn = sqlite3.connect(FRONTEND_DB_PATH)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("""
        CREATE TABLE IF NOT EXISTS pbx_servers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port TEXT NOT NULL,
            secret TEXT,
            is_active INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed default Staging server if none exist
    c.execute("SELECT COUNT(*) FROM pbx_servers")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO pbx_servers (id, name, host, port, secret, is_active)
            VALUES ('srv_staging', 'Staging PBX (13.126.90.199)', '13.126.90.199', '5000', ?, 1)
        """, (DEFAULT_API_KEY,))
    conn.commit()
    conn.close()

init_frontend_db()

def db_get_servers():
    conn = sqlite3.connect(FRONTEND_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, name, host, port, secret, is_active FROM pbx_servers ORDER BY created_at ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def db_save_server(srv):
    conn = sqlite3.connect(FRONTEND_DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO pbx_servers (id, name, host, port, secret, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        srv.get("id") or f"srv_{int(time.time())}",
        srv.get("name", "PBX Server"),
        srv.get("host", "127.0.0.1"),
        str(srv.get("port", "5000")),
        srv.get("secret", DEFAULT_API_KEY),
        1 if srv.get("is_active") else 0
    ))
    conn.commit()
    conn.close()

def db_delete_server(srv_id):
    conn = sqlite3.connect(FRONTEND_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM pbx_servers WHERE id = ?", (srv_id,))
    conn.commit()
    conn.close()

def db_log_audit(user, action, details):
    try:
        conn = sqlite3.connect(FRONTEND_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (user, action, details) VALUES (?, ?, ?)", (user, action, details))
        conn.commit()
        conn.close()
    except Exception:
        pass


class PBXFrontendHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split("?")[0]
        return super().translate_path(path)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()

    def do_POST(self):
        clean_path = self.path.split("?")[0]
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(post_data.decode("utf-8") or "{}")
        except Exception:
            payload = {}

        if clean_path == "/api/auth/login":
            user = (payload.get("username") or "").strip()
            pwd = payload.get("password") or ""

            if user == FRONTEND_ADMIN_USER and pwd == FRONTEND_ADMIN_PASS:
                token = base64.b64encode(f"{user}:{time.time()}".encode("utf-8")).decode("utf-8")
                db_log_audit(user, "LOGIN_SUCCESS", "Operator logged into Frontend Console")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                resp = {
                    "status": "success",
                    "message": "Optox Shield frontend authentication successful",
                    "token": token,
                    "user": user
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            else:
                db_log_audit(user or "anonymous", "LOGIN_FAILED", "Invalid credentials entered")
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                resp = {"status": "error", "message": "Invalid Optox Shield operator credentials"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return

        elif clean_path == "/api/frontend/servers":
            db_save_server(payload)
            db_log_audit("admin", "SAVE_SERVER", f"Saved PBX profile: {payload.get('name')}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "servers": db_get_servers()}).encode("utf-8"))
            return

        elif clean_path == "/api/frontend/audit":
            db_log_audit(payload.get("user", "admin"), payload.get("action", "EVENT"), payload.get("details", ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
            return

        return super().do_POST()

    def do_DELETE(self):
        clean_path = self.path.split("?")[0]
        if clean_path == "/api/frontend/servers":
            query = self.path.split("?")[1] if "?" in self.path else ""
            params = dict(qc.split("=") for qc in query.split("&") if "=" in qc)
            srv_id = params.get("id")
            if srv_id:
                db_delete_server(srv_id)
                db_log_audit("admin", "DELETE_SERVER", f"Removed PBX profile: {srv_id}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "servers": db_get_servers()}).encode("utf-8"))
            return
        return super().do_DELETE()

    def do_GET(self):
        clean_path = self.path.split("?")[0]
        if clean_path in ["/config.json", "/api/config"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            data = {
                "backend_host": DEFAULT_BACKEND_HOST,
                "backend_port": DEFAULT_BACKEND_PORT,
                "api_key": DEFAULT_API_KEY,
                "frontend_port": PORT,
                "frontend_host": HOST,
                "auth_required": True,
                "servers": db_get_servers()
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return
        elif clean_path == "/api/frontend/servers":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "servers": db_get_servers()}).encode("utf-8"))
            return
        return super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

class ReusableThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    dir_name = os.path.dirname(os.path.abspath(__file__))
    if dir_name:
        os.chdir(dir_name)
    with ReusableThreadingServer((HOST, PORT), PBXFrontendHandler) as httpd:
        print("=======================================================")
        print("  OPTOX SHIELD — FRONTEND SOC CONSOLE ACTIVE")
        print("=======================================================")
        print(f"  [+] Listening on: http://{HOST}:{PORT}")
        print(f"  [+] Frontend Admin: {FRONTEND_ADMIN_USER}")
        print(f"  [+] Default Backend Target: http://{DEFAULT_BACKEND_HOST}:{DEFAULT_BACKEND_PORT}")
        print("=======================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  [!] Frontend server stopped by user.")
