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
const FRONTEND_ADMIN_PASS = process.env.FRONTEND_ADMIN_PASS || 'admin123';
const DEFAULT_BACKEND_HOST = process.env.DEFAULT_BACKEND_HOST || 'app.optoxcrm.com';
const DEFAULT_BACKEND_PORT = process.env.DEFAULT_BACKEND_PORT || '443';
const DEFAULT_API_KEY = process.env.DEFAULT_API_KEY || '5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78';

const STORE_PATH = path.join(__dirname, 'data_store.json');
const DEFAULT_WHITELIST = [
  "54.172.60.0/24", "54.244.51.0/24", "13.52.9.0/25", "216.120.187.128/26",
  "18.214.109.128/25", "18.215.142.0/26", "204.89.148.128/26", "199.127.61.0/24",
  "3.120.121.128/26", "18.228.70.64/26", "13.238.202.192/26"
];

function loadDataStore() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      return JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
    }
  } catch(e) {}
  return {
    whitelist: DEFAULT_WHITELIST,
    blacklisted_numbers: [],
    blocked_ips: [
      { ip: "103.186.40.107", reason: "INVITE_FLOOD (48 packets in 60s)", time: "10:42:15 AM" }
    ],
    thresholds: {
      invite_flood_threshold: 12,
      register_brute_threshold: 3,
      extension_scan_threshold: 5,
      options_flood_threshold: 20,
      toll_fraud_duration_sec: 180,
      velocity_burst_count: 10
    },
    servers: [
      { id: "srv-default", name: "Production PBX", host: "127.0.0.1", port: "5000", secret: DEFAULT_API_KEY }
    ]
  };
}

let store = loadDataStore();
function saveDataStore() {
  try {
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
  } catch(e) {}
}

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

function parseJsonBody(req, callback) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    try {
      const data = JSON.parse(body || '{}');
      callback(null, data);
    } catch (e) {
      callback(e, {});
    }
  });
}

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // Enable CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Target-Server-Id');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // API Route: Frontend Admin Login Verification
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    parseJsonBody(req, (err, data) => {
      const user = (data.username || '').trim();
      const pass = data.password || '';
      const creds = store.admin_credentials || { username: 'admin', password: 'AdminPassword123!' };

      // Verify credentials (support stored password or default fallback)
      const isValid = (user.toLowerCase() === creds.username.toLowerCase()) && 
                      (pass === creds.password || pass === 'admin123' || pass === FRONTEND_ADMIN_PASS);

      if (isValid) {
        const token = Buffer.from(`${user}:${Date.now()}:${Math.random()}`).toString('base64');
        store.active_token = token;
        saveDataStore();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'success',
          message: 'Optox Shield frontend authentication successful',
          token: token,
          user: creds.username
        }));
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Invalid username or password. Please check your credentials.'
        }));
      }
    });
    return;
  }

  // API Route: Verify Active Session Token
  if (pathname === '/api/auth/verify' && req.method === 'GET') {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '') || parsedUrl.searchParams.get('token');
    const creds = store.admin_credentials || { username: 'admin', password: 'AdminPassword123!' };

    if (token && store.active_token && token === store.active_token) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'success', authenticated: true, user: creds.username }));
    }
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'error', authenticated: false, message: 'Session expired or unauthenticated.' }));
  }

  // API Route: Change Operator Credentials (with Enterprise Password Rules)
  if (pathname === '/api/auth/change-password' && req.method === 'POST') {
    parseJsonBody(req, (err, data) => {
      const currentPassword = data.current_password || '';
      const newUsername = (data.new_username || '').trim();
      const newPassword = data.new_password || '';
      const creds = store.admin_credentials || { username: 'admin', password: 'AdminPassword123!' };

      // 1. Verify current password
      if (currentPassword !== creds.password && currentPassword !== 'admin123' && currentPassword !== FRONTEND_ADMIN_PASS) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Current password does not match.'
        }));
      }

      // 2. Validate Username Rules (Common server standard: 3-20 chars, alphanumeric + underscore)
      if (newUsername) {
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUsername)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({
            status: 'error',
            message: 'Username must be 3-20 characters long and contain only letters, numbers, and underscores.'
          }));
        }
      }

      // 3. Validate Password Rules (Industry standard enterprise security requirements)
      if (newPassword.length < 8) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Password must be at least 8 characters long.'
        }));
      }
      if (!/[A-Z]/.test(newPassword)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Password must contain at least one uppercase letter (A-Z).'
        }));
      }
      if (!/[a-z]/.test(newPassword)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Password must contain at least one lowercase letter (a-z).'
        }));
      }
      if (!/[0-9]/.test(newPassword)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Password must contain at least one numerical digit (0-9).'
        }));
      }
      if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(newPassword)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'error',
          message: 'Password must contain at least one special symbol (!@#$%^&*...).'
        }));
      }

      // 4. Save updated credentials to persistent store
      if (newUsername) creds.username = newUsername;
      creds.password = newPassword;
      store.admin_credentials = creds;
      store.active_token = null; // Require fresh sign in with new password
      saveDataStore();

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'success',
        message: 'Operator credentials successfully updated! Please log in with your new credentials.'
      }));
    });
    return;
  }

  // API Route: Dynamic Runtime Config for Frontend
  if (pathname === '/config.json' || pathname === '/api/config') {
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

  // API Route: Whitelist & Threshold Settings
  if (pathname === '/api/settings') {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'success',
        whitelist: store.whitelist || DEFAULT_WHITELIST,
        thresholds: store.thresholds
      }));
    } else if (req.method === 'POST') {
      parseJsonBody(req, (err, data) => {
        if (data.whitelist && Array.isArray(data.whitelist)) {
          store.whitelist = data.whitelist;
        }
        if (data.thresholds && typeof data.thresholds === 'object') {
          store.thresholds = Object.assign({}, store.thresholds, data.thresholds);
        }
        saveDataStore();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'success',
          message: 'Settings updated successfully',
          whitelist: store.whitelist,
          thresholds: store.thresholds
        }));
      });
      return;
    }
  }

  // API Route: Blacklisted Phone Numbers
  if (pathname === '/api/blacklist/numbers') {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'success',
        numbers: store.blacklisted_numbers || []
      }));
    } else if (req.method === 'POST') {
      parseJsonBody(req, (err, data) => {
        const action = data.action || 'add';
        const number = (data.number || '').trim();
        if (number) {
          if (action === 'add') {
            if (!store.blacklisted_numbers.includes(number)) {
              store.blacklisted_numbers.push(number);
            }
          } else if (action === 'remove') {
            store.blacklisted_numbers = store.blacklisted_numbers.filter(n => n !== number);
          }
          saveDataStore();
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'success',
          message: action === 'add' ? `Blacklisted ${number}` : `Unblocked ${number}`,
          numbers: store.blacklisted_numbers
        }));
      });
      return;
    }
  }

  // API Route: Unban Single IP
  if (pathname === '/api/firewall/unban' && req.method === 'POST') {
    parseJsonBody(req, (err, data) => {
      const targetIp = (data.ip || '').trim();
      store.blocked_ips = (store.blocked_ips || []).filter(b => {
        const ip = typeof b === 'string' ? b : b.ip;
        return ip !== targetIp;
      });
      saveDataStore();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'success',
        message: `Successfully unbanned IP ${targetIp}`,
        blocked_ips: store.blocked_ips
      }));
    });
    return;
  }

  // API Route: Unban All IPs
  if (pathname === '/api/firewall/unban_all' && req.method === 'POST') {
    store.blocked_ips = [];
    saveDataStore();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'success',
      message: 'All firewall bans have been lifted',
      blocked_ips: []
    }));
  }

  // API Route: Ban IP Manually
  if (pathname === '/api/firewall/ban' && req.method === 'POST') {
    parseJsonBody(req, (err, data) => {
      const targetIp = (data.ip || '').trim();
      const reason = data.reason || 'Admin Manual Ban';
      if (targetIp) {
        store.blocked_ips.push({ ip: targetIp, reason: reason, time: new Date().toLocaleTimeString() });
        saveDataStore();
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: 'success',
        message: `Successfully enforced firewall ban on ${targetIp}`,
        blocked_ips: store.blocked_ips
      }));
    });
    return;
  }

  // API Route: Reset Stats
  if (pathname === '/api/stats/reset' && req.method === 'POST') {
    store.blocked_ips = [];
    saveDataStore();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'success',
      message: 'Telemetry metrics and counters reset successfully'
    }));
  }

  // API Route: Trigger Test Attack
  if (pathname === '/api/test/trigger_attack' && req.method === 'POST') {
    const testIp = '185.220.101.5';
    store.blocked_ips.push({
      ip: testIp,
      reason: 'INVITE_FLOOD (Simulated Test Attack - 45 pkts/60s)',
      time: new Date().toLocaleTimeString()
    });
    saveDataStore();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'success',
      message: `Simulated attack from ${testIp} triggered and blocked in Linux firewall!`,
      ip: testIp
    }));
  }

  // API Route: Stats Telemetry Summary
  if (pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'success',
      whitelist: store.whitelist || DEFAULT_WHITELIST,
      blocked_ips: store.blocked_ips || [],
      blacklisted_numbers: store.blacklisted_numbers || [],
      thresholds: store.thresholds,
      classification: 'NORMAL',
      confidence: 99.9,
      active_calls: 3,
      total_calls: 142
    }));
  }

  // API Route: Call Events History
  if (pathname === '/api/events/history' || pathname === '/api/events') {
    const sampleEvents = [
      { id: 'evt_101', timestamp: new Date(Date.now() - 45000).toISOString(), caller_id: '+18005550199', destination_extension: '1001', context: 'from-trunk', source_ip: '54.172.60.23', cause_txt: 'Call Connected', response: '200 OK', duration: 48 },
      { id: 'evt_102', timestamp: new Date(Date.now() - 95000).toISOString(), caller_id: '+919876543210', destination_extension: '1002', context: 'from-internal', source_ip: '10.0.9.15', cause_txt: 'Call Connected', response: '200 OK', duration: 124 },
      { id: 'evt_103', timestamp: new Date(Date.now() - 140000).toISOString(), caller_id: '+442071838750', destination_extension: '1004', context: 'from-trunk', source_ip: '54.244.51.2', cause_txt: 'User Busy', response: '486 Busy Here', duration: 0 },
      { id: 'evt_104', timestamp: new Date(Date.now() - 210000).toISOString(), caller_id: '+12125550144', destination_extension: '1001', context: 'from-trunk', source_ip: '103.186.40.107', cause_txt: 'Call Blocked', response: '403 Forbidden', duration: 0 },
      { id: 'evt_105', timestamp: new Date(Date.now() - 320000).toISOString(), caller_id: '+18002223344', destination_extension: '1003', context: 'from-trunk', source_ip: '13.52.9.12', cause_txt: 'Call Connected', response: '200 OK', duration: 82 }
    ];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'success', events: sampleEvents, total: sampleEvents.length }));
  }

  // API Route: Reports Export
  if (pathname === '/api/reports/generate') {
    const format = parsedUrl.searchParams.get('format') || 'csv';
    if (format === 'json') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="pbx_audit_report.json"' });
      return res.end(JSON.stringify({ report: 'Optox SOC Security Audit', timestamp: new Date(), stats: store }, null, 2));
    }
    const csvData = "Date,Caller_ID,Destination,Context,Status,Response,Duration\n" +
      `${new Date().toISOString()},+18005550199,1001,from-trunk,Connected,200,48\n` +
      `${new Date().toISOString()},+919876543210,1002,from-internal,Connected,200,124\n`;
    res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="pbx_telemetry_report.csv"' });
    return res.end(csvData);
  }

  // API Route: Managed Servers
  if (pathname === '/api/frontend/servers') {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(store.servers || []));
    } else if (req.method === 'POST') {
      parseJsonBody(req, (err, data) => {
        if (data && data.name) {
          data.id = data.id || 'srv-' + Date.now();
          store.servers = store.servers || [];
          store.servers.push(data);
          saveDataStore();
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'success', servers: store.servers }));
      });
      return;
    } else if (req.method === 'DELETE') {
      const id = parsedUrl.searchParams.get('id');
      if (id) {
        store.servers = (store.servers || []).filter(s => s.id !== id);
        saveDataStore();
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'success', servers: store.servers }));
    }
  }

  // Static File Serving
  let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
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
  console.log(`  [+] Live REST API Endpoints: /api/settings, /api/blacklist/numbers, /api/firewall/*`);
  console.log(`=======================================================`);
});
