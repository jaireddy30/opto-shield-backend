const http = require('http');
const fs = require('fs');
const path = require('path');

// Simple .env file parser
function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    lines.forEach(line => {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match) {
        const key = match[1];
        let value = match[2] || '';
        if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
        if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);
        process.env[key] = value.trim();
      }
    });
  }
}

loadEnv();

const HOST = process.env.HOST || '0.0.0.0';
const PORT = parseInt(process.env.PORT || '9000', 10);
const FRONTEND_ADMIN_USER = process.env.FRONTEND_ADMIN_USER || 'admin';
const FRONTEND_ADMIN_PASS = process.env.FRONTEND_ADMIN_PASS || 'pbx-shield-admin-2026';
const DEFAULT_BACKEND_HOST = process.env.DEFAULT_BACKEND_HOST || '13.126.90.199';
const DEFAULT_BACKEND_PORT = process.env.DEFAULT_BACKEND_PORT || '5000';
const DEFAULT_API_KEY = process.env.DEFAULT_API_KEY || '5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78';

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];

  // Enable CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // API Route: Frontend Admin Login Verification
  if (url === '/api/auth/login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const user = (data.username || '').trim();
        const pass = data.password || '';

        if (user === FRONTEND_ADMIN_USER && pass === FRONTEND_ADMIN_PASS) {
          const token = Buffer.from(`${user}:${Date.now()}`).toString('base64');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({
            status: 'success',
            message: 'Optox Shield frontend authentication successful',
            token: token,
            user: user
          }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({
            status: 'error',
            message: 'Invalid Optox Shield operator credentials'
          }));
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'error', message: 'Malformed JSON payload' }));
      }
    });
    return;
  }

  // API Route: Dynamic Runtime Config for Frontend
  if (url === '/config.json' || url === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      backend_host: DEFAULT_BACKEND_HOST,
      backend_port: DEFAULT_BACKEND_PORT,
      api_key: DEFAULT_API_KEY,
      frontend_port: PORT,
      frontend_host: HOST,
      auth_required: true
    }));
  }

  let filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
  const ext = path.extname(filePath).toLowerCase();

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>');
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'text/plain' });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`=======================================================`);
  console.log(`  OPTOX SHIELD — FRONTEND SOC CONSOLE ACTIVE`);
  console.log(`=======================================================`);
  console.log(`  [+] Listening on: http://${HOST}:${PORT} (0.0.0.0/0)`);
  console.log(`  [+] Frontend Admin: ${FRONTEND_ADMIN_USER}`);
  console.log(`  [+] Default Backend Target: http://${DEFAULT_BACKEND_HOST}:${DEFAULT_BACKEND_PORT}`);
  console.log(`=======================================================`);
});
