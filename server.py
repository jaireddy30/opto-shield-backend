import http.server
import socketserver
import os
import json

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
DEFAULT_BACKEND_HOST = os.getenv("DEFAULT_BACKEND_HOST", "13.126.90.199")
DEFAULT_BACKEND_PORT = os.getenv("DEFAULT_BACKEND_PORT", "5000")
DEFAULT_API_KEY = os.getenv("DEFAULT_API_KEY", "5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78")

class PBXFrontendHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Strip query parameters
        path = path.split("?")[0]
        return super().translate_path(path)

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
                "frontend_host": HOST
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return
        return super().do_GET()

if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    with socketserver.TCPServer((HOST, PORT), PBXFrontendHandler) as httpd:
        print("=======================================================")
        print("  PBX SHIELD — FRONTEND SOC CONSOLE ACTIVE")
        print("=======================================================")
        print(f"  [+] Listening on: http://{HOST}:{PORT} (0.0.0.0/0)")
        print(f"  [+] Default Backend Target: http://{DEFAULT_BACKEND_HOST}:{DEFAULT_BACKEND_PORT}")
        print("=======================================================")
        httpd.serve_forever()
