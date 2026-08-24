import http.server
import socketserver
import os
import json
import base64
import time

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
DEFAULT_BACKEND_HOST = os.getenv("DEFAULT_BACKEND_HOST", "13.126.90.199")
DEFAULT_BACKEND_PORT = os.getenv("DEFAULT_BACKEND_PORT", "5000")
DEFAULT_API_KEY = os.getenv("DEFAULT_API_KEY", "5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78")

class PBXFrontendHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split("?")[0]
        return super().translate_path(path)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_POST(self):
        clean_path = self.path.split("?")[0]
        if clean_path == "/api/auth/login":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode("utf-8") or "{}")
                user = (data.get("username") or "").strip()
                pwd = data.get("password") or ""

                if user == FRONTEND_ADMIN_USER and pwd == FRONTEND_ADMIN_PASS:
                    token = base64.b64encode(f"{user}:{time.time()}".encode("utf-8")).decode("utf-8")
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
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    resp = {"status": "error", "message": "Invalid Optox Shield operator credentials"}
                    self.wfile.write(json.dumps(resp).encode("utf-8"))
                    return
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))
                return

        return super().do_POST()

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
                "auth_required": True
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return
        return super().do_GET()

if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    with socketserver.TCPServer((HOST, PORT), PBXFrontendHandler) as httpd:
        print("=======================================================")
        print("  OPTOX SHIELD — FRONTEND SOC CONSOLE ACTIVE")
        print("=======================================================")
        print(f"  [+] Listening on: http://{HOST}:{PORT} (0.0.0.0/0)")
        print(f"  [+] Frontend Admin: {FRONTEND_ADMIN_USER}")
        print(f"  [+] Default Backend Target: http://{DEFAULT_BACKEND_HOST}:{DEFAULT_BACKEND_PORT}")
        print("=======================================================")
        httpd.serve_forever()
