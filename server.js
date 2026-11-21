'use strict';
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// =====================================================================
//  1) ตั้งค่า (Environment variables)
// =====================================================================
const env = process.env;
const num = (value, fallback) => Number(value) || fallback;

const { MONGODB_URI, ADMIN_PASSWORD } = env;
const PORT = env.PORT || 3000;
const ADMIN = `/${env.SECRET_ADMIN_PATH || 'void-admin-9988'}`;
const DASH = `${ADMIN}/dashboard`;

// true = ลิงก์ Raw ไม่ตอบเบราว์เซอร์ (ยกเว้นแอดมินที่ล็อกอินอยู่) ปิดได้ด้วย RAW_GAME_ONLY=false
const GAME_ONLY = env.RAW_GAME_ONLY !== 'false';
const BLOCK_TEXT = env.BLOCK_TEXT || 'ดูอะไร นะ Error';

// กันยิงถี่ ปรับได้ด้วย RATE_LIMIT_RAW, RATE_LIMIT_ALL, RATE_BAN_MINUTES
const RATE_RAW = num(env.RATE_LIMIT_RAW, 60);   // ลิงก์ /raw ต่อนาทีต่อ IP
const RATE_ALL = num(env.RATE_LIMIT_ALL, 240);  // ทุกเส้นทางรวมกันต่อนาทีต่อ IP
const RATE_KEY = num(env.RATE_LIMIT_KEY, 30);   // ขอคีย์ใหม่ (/api/key) ต่อนาทีต่อ IP
const BAN_MS = num(env.RATE_BAN_MINUTES, 5) * 60 * 1000;

// ระบบคีย์: ตัวโหลดขอคีย์สุ่มใหม่ทุกครั้งก่อนดึงสคริปต์ คีย์ใช้ได้ครั้งเดียวและหมดอายุเอง
// ปิดได้ด้วย KEY_SYSTEM=false (ปิด = /raw เปิดได้ตรงๆ ไม่ต้องมีคีย์)
const KEY_SYSTEM = env.KEY_SYSTEM !== 'false';
const KEY_TTL_MS = 2 * 60 * 1000;
// ชื่อไฟล์ที่ไม่ต้องมีคีย์ก็เปิด /raw ได้ (คั่นด้วยจุลภาค) เช่น KEY_EXEMPT=loader,Script2
const KEY_EXEMPT = new Set(String(env.KEY_EXEMPT || '').split(',').map(x => x.trim()).filter(Boolean));

// กันเดารหัสผ่าน: ผิด 5 ครั้งต่อ IP แล้วล็อก 15 นาที
const LOGIN_MAX_FAILS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

// แคชเนื้อสคริปต์ในหน่วยความจำ ลดภาระฐานข้อมูลเวลาโดนยิงถี่
const CACHE_TTL_MS = 30 * 1000;
const CACHE_MAX_ITEMS = 500;

if (!MONGODB_URI || !ADMIN_PASSWORD) {
    console.error('❌ ต้องตั้งค่า MONGODB_URI และ ADMIN_PASSWORD ใน Environment variables');
    process.exit(1);
}

let SESSION_SECRET = env.SESSION_SECRET;
if (!SESSION_SECRET) {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️ ไม่ได้ตั้ง SESSION_SECRET (สุ่มให้ชั่วคราว ล็อกอินจะหลุดเมื่อเซิร์ฟเวอร์รีสตาร์ต)');
}

// =====================================================================
//  2) Helpers
// =====================================================================
const esc = s => String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));
const str = v => (typeof v === 'string' ? v : '');
const validName = n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(n);
const cleanName = n => str(n).trim().replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._-]+/, '').slice(0, 100);
const normalizeNewlines = s => s.replace(/\r\n/g, '\n');

const fmtSize = n => (n < 1024 ? `${n} B`
    : n < 1048576 ? `${(n / 1024).toFixed(1)} KB`
    : `${(n / 1048576).toFixed(1)} MB`);
const fmtDate = d => new Date(d).toLocaleString('th-TH', {
    timeZone: 'Asia/Bangkok', dateStyle: 'medium', timeStyle: 'short',
});

// เทียบสตริงแบบ timing-safe (hash ก่อนเพื่อให้ความยาวเท่ากัน)
const sha256 = v => crypto.createHash('sha256').update(String(v)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(a), sha256(b));

// =====================================================================
//  3) Database
// =====================================================================
const Script = mongoose.model('Script', new mongoose.Schema({
    filename: { type: String, required: true, unique: true, trim: true },
    content: { type: String, required: true },
}, { timestamps: true }));

// คีย์แบบใช้ครั้งเดียว หมดอายุเองด้วย TTL index ของ MongoDB
const Key = mongoose.model('Key', new mongoose.Schema({
    filename: { type: String, required: true },
    device: { type: String, required: true },
    key: { type: String, required: true, unique: true },
    used: { type: Boolean, default: false },
    expiresAt: { type: Date, required: true, expires: 0 },
}));

const genKey = () => crypto.randomBytes(20).toString('hex');
const validDevice = d => /^[A-Za-z0-9]{3,64}$/.test(d);

// Adler-32 checksum ให้ตัวโหลดฝั่งเกมเช็คได้เองว่าไฟล์ที่โหลดมาครบไม่เพี้ยน
function adler32(buf) {
    let a = 1, b = 0;
    for (let i = 0; i < buf.length; i++) {
        a = (a + buf[i]) % 65521;
        b = (b + a) % 65521;
    }
    return ((b << 16) | a) >>> 0;
}

const scriptCache = new Map(); // ชื่อไฟล์ -> { content, exp } (เก็บชื่อที่ไม่มีอยู่ด้วย)

async function getScript(name) {
    const hit = scriptCache.get(name);
    if (hit && hit.exp > Date.now()) return hit.content;

    const doc = await Script.findOne({ filename: name }, 'content').lean();
    const content = doc ? doc.content : null;

    if (scriptCache.size >= CACHE_MAX_ITEMS) scriptCache.clear();
    scriptCache.set(name, { content, exp: Date.now() + CACHE_TTL_MS });
    return content;
}

async function saveScript(name, content) {
    await Script.findOneAndUpdate({ filename: name }, { content }, { upsert: true });
    scriptCache.delete(name);
}

// =====================================================================
//  4) Middleware
// =====================================================================
const hits = new Map();       // "all:ip" / "raw:ip" -> { n, reset }
const banned = new Map();     // ip -> เวลาที่หมดแบน
const loginFails = new Map(); // ip -> { n, reset }

const over = (key, limit) => {
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset <= now) {
        h = { n: 0, reset: now + 60 * 1000 };
        hits.set(key, h);
    }
    return ++h.n > limit;
};

const tooManyRequests = (res, ms) => {
    res.set('Retry-After', String(Math.ceil(ms / 1000)));
    return res.status(429).type('text/plain').send('Too many requests');
};

function rateLimit(req, res, next) {
    const { ip } = req;
    const now = Date.now();
    const until = banned.get(ip);
    if (until > now) return tooManyRequests(res, until - now);

    if (over(`all:${ip}`, RATE_ALL)
        || (req.path.startsWith('/raw/') && over(`raw:${ip}`, RATE_RAW))
        || (req.path.startsWith('/api/key/') && over(`key:${ip}`, RATE_KEY))) {
        banned.set(ip, now + BAN_MS);
        return tooManyRequests(res, BAN_MS);
    }
    next();
}

function securityHeaders(req, res, next) {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
    });
    next();
}

// เก็บ session ลง MongoDB ถ้าติดตั้ง connect-mongo ไว้ (npm i connect-mongo) ไม่งั้นใช้ memory
function createSessionStore() {
    try {
        const MongoStore = require('connect-mongo');
        const store = (MongoStore.default || MongoStore).create({ mongoUrl: MONGODB_URI });
        console.log('🗄️ Session store: MongoDB');
        return store;
    } catch (e) {
        if (e.code !== 'MODULE_NOT_FOUND') throw e;
        console.log('ℹ️ Session store: memory (ติดตั้ง connect-mongo เพื่อไม่ให้ล็อกอินหลุดตอนรีสตาร์ต)');
        return undefined;
    }
}

const requireAuth = (req, res, next) => (
    req.session.loggedIn ? next() : res.status(403).send('Access Denied')
);

const checkCsrf = (req, res, next) => {
    const token = str(req.body && req.body._csrf);
    if (!req.session.csrf || !safeEqual(token, req.session.csrf)) {
        return res.status(403).send('Invalid CSRF token');
    }
    next();
};

// ตรวจว่าเป็น "การเปิดหน้าเว็บของเบราว์เซอร์" จริงๆ จากหัวที่เบราว์เซอร์ส่งเฉพาะตอนเปิดหน้า
// (ไม่ดู User-Agent เพราะ executor บางตัวใช้ Mozilla/... เหมือนกัน)
const looksLikeBrowser = req => str(req.get('accept')).toLowerCase().includes('text/html')
    || req.get('sec-fetch-mode') === 'navigate'
    || req.get('sec-fetch-dest') === 'document'
    || !!req.get('upgrade-insecure-requests');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(rateLimit);
app.use(securityHeaders);
app.use(session({
    name: 'vh.sid',
    secret: SESSION_SECRET,
    store: createSessionStore(),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: 'auto' },
}));

// /save รับก้อนใหญ่ได้ แต่เฉพาะแอดมินที่ล็อกอิน ส่วนที่เหลือจำกัด 100 KB กันคนส่งข้อมูลก้อนใหญ่มาถล่ม
app.use('/save', requireAuth, express.urlencoded({ limit: '10mb', extended: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ limit: '100kb', extended: false }));

// ล้างข้อมูลหมดอายุทุกนาที
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
    for (const [k, v] of banned) if (v <= now) banned.delete(k);
    for (const [k, v] of loginFails) if (v.reset <= now) loginFails.delete(k);
}, 60 * 1000).unref();

const isLoginLocked = ip => {
    const f = loginFails.get(ip);
    return !!f && f.reset > Date.now() && f.n >= LOGIN_MAX_FAILS;
};
const recordLoginFail = ip => {
    let f = loginFails.get(ip);
    if (!f || f.reset <= Date.now()) {
        f = { n: 0, reset: Date.now() + LOGIN_WINDOW_MS };
        loginFails.set(ip, f);
    }
    f.n++;
};

// =====================================================================
//  5) หน้าเว็บ (Views)
// =====================================================================
const FONTS = 'https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Thai:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap';

const CSS = `
:root {
  --bg: #eef1f5;
  --surface: #ffffff;
  --ink: #14213d;
  --muted: #526072;
  --line: #d6dde8;
  --accent: #0f766e;
  --accent-hover: #0b5d57;
  --tint: #e0f3ef;
  --danger: #c2334d;
  --danger-tint: #fbe9ed;
  --code-bg: #101828;
  --code-ink: #e6edf7;
  --font: 'IBM Plex Sans Thai', 'Noto Sans Thai', Tahoma, sans-serif;
  --mono: 'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body {
  margin: 0; min-height: 100vh; background: var(--bg); color: var(--ink);
  font: 16px/1.65 var(--font); -webkit-text-size-adjust: 100%;
}
:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
h1, h2 { margin: 0; line-height: 1.3; }
h1 { font-size: 22px; }
h2 { font-size: 17px; overflow-wrap: anywhere; }
p { margin: 0; }
.sub { color: var(--muted); font-size: 14px; }

/* แบรนด์ */
.brand { display: inline-flex; align-items: center; gap: 10px; font-weight: 700; font-size: 20px; letter-spacing: -0.01em; }
.mark { width: 22px; height: 22px; border: 4px solid var(--ink); border-radius: 50%; flex: none; }

/* โครงหน้า */
.shell { max-width: 1120px; margin: 0 auto; padding: 20px 20px 56px; }
.bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding-bottom: 18px; margin-bottom: 24px; border-bottom: 1px solid var(--line); }
.bar form { margin: 0; }
.grid { display: grid; gap: 24px; }
.side { display: grid; gap: 24px; }
@media (min-width: 900px) {
  .grid { grid-template-columns: minmax(0, 1fr) minmax(0, 1.1fr); align-items: start; }
  .side { position: sticky; top: 20px; }
}
.center { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }

/* กล่องเนื้อหา */
.panel { background: var(--surface); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
.panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; padding: 16px 18px; border-bottom: 1px solid var(--line); }
.panel-body { padding: 18px; }
.search-wrap { padding: 14px 18px 0; }
.empty { padding: 28px 18px; text-align: center; color: var(--muted); }

/* ปุ่ม */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  min-height: 42px; padding: 0 16px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--surface); color: var(--ink); font: 600 14px/1 var(--font);
  text-decoration: none; cursor: pointer; transition: background .15s, border-color .15s;
}
.btn:hover { border-color: var(--ink); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
.btn-danger { color: var(--danger); }
.btn-danger:hover { border-color: var(--danger); background: var(--danger-tint); }
.btn-sm { min-height: 36px; padding: 0 12px; font-size: 13px; }
.btn-block { display: flex; width: 100%; }
.row { display: flex; gap: 10px; flex-wrap: wrap; }
.grow { flex: 1; }

/* ฟอร์ม */
label { display: block; margin: 0 0 6px; font-size: 14px; font-weight: 600; }
.input {
  width: 100%; margin-bottom: 14px; padding: 11px 13px; background: var(--surface);
  border: 1px solid var(--line); border-radius: 8px; color: var(--ink); font: 15px var(--font);
}
.input:focus { border-color: var(--accent); }
.input[readonly] { background: #f4f6f9; color: var(--muted); }
.code { font-family: var(--mono); font-size: 14px; }
textarea.code {
  min-height: 340px; resize: vertical; overflow: auto; white-space: pre; tab-size: 4; line-height: 1.55;
  background: var(--code-bg); border-color: var(--code-bg); color: var(--code-ink);
}
textarea.code::placeholder { color: #7f8ba0; }
input[type=file] { padding: 9px 11px; }

/* รายการไฟล์ */
.files { list-style: none; margin: 0; padding: 0; }
.file { display: grid; gap: 12px; padding: 16px 18px; border-bottom: 1px solid var(--line); }
.file:last-child { border-bottom: 0; }
.file[aria-current="true"] { background: #f4faf9; box-shadow: inset 4px 0 0 var(--accent); }
.name { font-family: var(--mono); font-size: 15px; font-weight: 500; overflow-wrap: anywhere; }
.meta { display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 13px; }
.ops { display: flex; flex-wrap: wrap; gap: 8px; }
.ops form { margin: 0; }

/* ข้อความแจ้งผล */
.toast { margin-bottom: 18px; padding: 12px 14px; border-radius: 8px; font-weight: 600; font-size: 15px; }
.toast.ok { background: var(--tint); color: #0a4f49; border: 1px solid #a9ddd4; }
.toast.err { background: var(--danger-tint); color: #8f1f35; border: 1px solid #f0b6c2; }

/* หน้าแรก / ล็อกอิน */
.hero { text-align: center; display: grid; gap: 14px; justify-items: center; }
.brand-xl { font-size: clamp(40px, 12vw, 72px); gap: 16px; line-height: 1.1; }
.brand-xl .mark { width: .8em; height: .8em; border-width: .14em; }
.status { display: inline-flex; align-items: center; gap: 8px; padding: 6px 16px; border: 1px solid var(--line); border-radius: 999px; background: var(--surface); font-size: 14px; font-weight: 500; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #17a673; }
.login { width: 100%; max-width: 380px; padding: 28px; display: grid; gap: 10px; }
.login .brand { margin-bottom: 8px; }
.login form { margin-top: 12px; }

@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
`;

const CLIENT_JS = `
(function () {
  function flash(btn, text) {
    var label = btn.getAttribute('data-label') || btn.textContent;
    btn.setAttribute('data-label', label);
    btn.textContent = text;
    setTimeout(function () { btn.textContent = label; }, 1400);
  }
  function copy(text, btn) {
    function done() { flash(btn, 'คัดลอกแล้ว'); }
    function fallback() {
      var t = document.createElement('textarea');
      t.value = text; document.body.appendChild(t); t.select();
      try { document.execCommand('copy'); done(); } catch (e) { flash(btn, 'คัดลอกไม่ได้'); }
      document.body.removeChild(t);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-copy]');
    if (btn) copy(btn.getAttribute('data-copy'), btn);
  });

  document.addEventListener('submit', function (e) {
    var msg = e.target.getAttribute('data-confirm');
    if (msg && !confirm(msg)) e.preventDefault();
  });

  var search = document.getElementById('q');
  var empty = document.getElementById('empty');
  if (search) search.addEventListener('input', function () {
    var v = search.value.trim().toLowerCase(), shown = 0;
    document.querySelectorAll('.file').forEach(function (li) {
      var hide = !!v && li.getAttribute('data-name').indexOf(v) < 0;
      li.hidden = hide;
      if (!hide) shown++;
    });
    if (empty) { empty.textContent = 'ไม่พบไฟล์ที่ตรงกับคำค้น'; empty.hidden = shown > 0; }
  });

  var toast = document.querySelector('.toast.ok');
  if (toast) setTimeout(function () { toast.hidden = true; }, 4000);

  if (location.search.indexOf('m=') > -1) history.replaceState(null, '', location.pathname);
})();
`;

const MESSAGES = {
    saved: ['ok', 'บันทึกแล้ว'],
    uploaded: ['ok', 'อัปโหลดแล้ว'],
    deleted: ['ok', 'ลบแล้ว'],
    exists: ['err', 'มีชื่อไฟล์นี้อยู่แล้ว (กดแก้ไขที่ไฟล์เดิมแทน)'],
    badname: ['err', 'ชื่อไฟล์ใช้ได้เฉพาะ A-Z a-z 0-9 . _ - (ไม่เกิน 100 ตัว)'],
    empty: ['err', 'กรุณาใส่เนื้อหา'],
    nofile: ['err', 'ไม่มีไฟล์อัปโหลด'],
    badext: ['err', 'อัปโหลดได้เฉพาะไฟล์ .lua หรือ .txt'],
    toolarge: ['err', 'ไฟล์ใหญ่เกิน 10 MB'],
    notfound: ['err', 'ไม่พบไฟล์นี้'],
};

const page = (title, body, script = '') => `<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<style>${CSS}</style>
</head>
<body>${body}${script ? `<script>${script}</script>` : ''}</body>
</html>`;

const homeView = () => page('VOID HUB', `
<main class="center">
  <div class="hero">
    <div class="brand brand-xl"><span class="mark"></span>VOID HUB</div>
    <p class="sub">ระบบโฮสต์สคริปต์ออนไลน์</p>
    <span class="status"><span class="dot"></span>ระบบออนไลน์</span>
  </div>
</main>`);

const loginView = error => page('เข้าสู่ระบบแอดมิน', `
<main class="center">
  <section class="panel login">
    <div class="brand"><span class="mark"></span>VOID HUB</div>
    <h1>เข้าสู่ระบบแอดมิน</h1>
    <p class="sub">กรอกรหัสผ่านเพื่อจัดการไฟล์สคริปต์</p>
    ${error ? `<div class="toast err" role="alert">${esc(error)}</div>` : ''}
    <form method="POST" action="/login">
      <label for="pw">รหัสผ่าน</label>
      <input class="input" id="pw" type="password" name="password" autocomplete="current-password" autofocus required>
      <button class="btn btn-primary btn-block">เข้าสู่ระบบ</button>
    </form>
  </section>
</main>`);

// หน้าที่แสดงเมื่อถูกบล็อก / ไม่พบไฟล์ (ใช้แบบเดียวกันทั้งสองกรณี คนนอกจะเดาไม่ได้ว่ามีไฟล์จริงไหม)
// ใส่รูปโดยวางไฟล์ block.png (หรือ .jpg .jpeg .gif .webp) ไว้โฟลเดอร์เดียวกับ server.js
const BLOCK_IMG = ['png', 'jpg', 'jpeg', 'gif', 'webp']
    .map(ext => path.join(__dirname, `block.${ext}`))
    .find(file => fs.existsSync(file));

const denyView = () => `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Error</title>
<style>html,body{margin:0;height:100%;background:#111;display:flex;align-items:center;justify-content:center}
img{max-width:100%;max-height:100vh}p{color:#ccc;font:20px sans-serif}</style></head>
<body>${BLOCK_IMG ? '<img src="/blocked-image" alt="">' : `<p>${esc(BLOCK_TEXT)}</p>`}</body></html>`;

const deny = res => res
    .status(404)
    .set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
    .send(denyView());

// สร้างสคริปต์ตัวโหลดฝั่งเกม: ขอคีย์สุ่มใหม่ -> ดึงสคริปต์ด้วยคีย์ -> เช็คขนาดและ checksum -> รัน (ลองใหม่ได้ 3 ครั้ง)
function buildLoader(base, filename) {
    const url = `${base}/raw/${encodeURIComponent(filename)}`;
    if (!KEY_SYSTEM) return `loadstring(game:HttpGet("${url}"))()`;
    return [
        `local Base,File="${base}","${encodeURIComponent(filename)}"`,
        `local HS=game:GetService("HttpService")`,
        `local function dev() return ("%d%d"):format(math.random(1e5,9e5),math.floor(tick()*1000)%1e6) end`,
        `local function adler32(str)`,
        `  local a,b=1,0`,
        `  for i=1,#str do a=(a+string.byte(str,i))%65521;b=(b+a)%65521 end`,
        `  return b*65536+a`,
        `end`,
        `local function attempt()`,
        `  local Dev=dev()`,
        `  local ok,res=pcall(function() return HS:JSONDecode(game:HttpGet(Base.."/api/key/"..File.."?device="..Dev)) end)`,
        `  if not ok or not res or not res.key then return nil,"ขอคีย์ไม่สำเร็จ" end`,
        `  local ok2,code=pcall(function() return game:HttpGet(Base.."/raw/"..File.."?key="..res.key.."&device="..Dev) end)`,
        `  if not ok2 or type(code)~="string" or code=="" then return nil,"โหลดสคริปต์ไม่สำเร็จ" end`,
        `  if res.len and #code~=res.len then return nil,"ขนาดไฟล์ไม่ตรง (โหลดมาไม่ครบ)" end`,
        `  if res.checksum and adler32(code)~=res.checksum then return nil,"เช็คซัมไม่ตรง (ไฟล์เพี้ยน)" end`,
        `  return code`,
        `end`,
        `local code,err`,
        `for i=1,3 do`,
        `  code,err=attempt()`,
        `  if code then break end`,
        `  warn("[VOID HUB] ลองครั้งที่ "..i.." ไม่สำเร็จ: "..tostring(err))`,
        `  if i<3 then pcall(task.wait,1) end`,
        `end`,
        `if not code then warn("[VOID HUB] โหลดสคริปต์ไม่สำเร็จหลังลอง 3 ครั้ง: "..tostring(err)) return end`,
        `loadstring(code)()`,
    ].join('\n');
}

function fileRow(s, { base, csrfField, editingName }) {
    const url = `${base}/raw/${encodeURIComponent(s.filename)}`;
    const loader = buildLoader(base, s.filename);
    const current = s.filename === editingName ? ' aria-current="true"' : '';
    return `
    <li class="file" data-name="${esc(s.filename.toLowerCase())}"${current}>
      <div>
        <div class="name">${esc(s.filename)}</div>
        <div class="meta">
          <span>${fmtSize(s.size)}</span>
          ${s.updatedAt ? `<span>อัปเดต ${esc(fmtDate(s.updatedAt))}</span>` : ''}
        </div>
      </div>
      <div class="ops">
        <button type="button" class="btn btn-primary btn-sm" data-copy="${esc(loader)}">คัดลอกตัวโหลด</button>
        <button type="button" class="btn btn-sm" data-copy="${esc(url)}">คัดลอกลิงก์</button>
        <a class="btn btn-sm" href="${esc(url)}" target="_blank" rel="noopener">เปิด Raw</a>
        <a class="btn btn-sm" href="?edit=${encodeURIComponent(s.filename)}#editor">แก้ไข</a>
        <form method="POST" action="/delete" data-confirm="${esc(`ลบไฟล์ ${s.filename} ออกจากระบบ?`)}">
          ${csrfField}<input type="hidden" name="filename" value="${esc(s.filename)}">
          <button class="btn btn-sm btn-danger">ลบ</button>
        </form>
      </div>
    </li>`;
}

function dashboardView({ csrf, base, scripts, editing, message }) {
    const csrfField = `<input type="hidden" name="_csrf" value="${esc(csrf)}">`;
    const totalSize = scripts.reduce((sum, s) => sum + s.size, 0);
    const [type, text] = message || [];
    const rows = scripts
        .map(s => fileRow(s, { base, csrfField, editingName: editing && editing.filename }))
        .join('');

    return page('Void Hub - แดชบอร์ด', `
<div class="shell">
  <header class="bar">
    <div class="brand"><span class="mark"></span>VOID HUB</div>
    <form method="POST" action="/logout">${csrfField}<button class="btn btn-sm">ออกจากระบบ</button></form>
  </header>

  ${text ? `<div class="toast ${type}" role="status">${esc(text)}</div>` : ''}

  <div class="grid">
    <section class="panel" aria-labelledby="files-title">
      <div class="panel-head">
        <h2 id="files-title">ไฟล์ในระบบ</h2>
        <span class="sub">${scripts.length} ไฟล์ รวม ${fmtSize(totalSize)}</span>
      </div>
      ${scripts.length > 4 ? '<div class="search-wrap"><input class="input" type="search" id="q" placeholder="ค้นหาชื่อไฟล์" aria-label="ค้นหาชื่อไฟล์"></div>' : ''}
      <ul class="files">${rows}</ul>
      <p class="empty" id="empty"${scripts.length ? ' hidden' : ''}>ยังไม่มีไฟล์ในระบบ สร้างไฟล์ใหม่หรืออัปโหลดได้เลย</p>
    </section>

    <div class="side">
      <section class="panel" id="editor" aria-labelledby="editor-title">
        <div class="panel-head">
          <h2 id="editor-title">${editing ? `แก้ไข ${esc(editing.filename)}` : 'สร้างไฟล์ใหม่'}</h2>
        </div>
        <form class="panel-body" method="POST" action="/save">
          ${csrfField}<input type="hidden" name="mode" value="${editing ? 'edit' : 'new'}">
          <label for="filename">ชื่อไฟล์</label>
          <input class="input code" id="filename" type="text" name="filename" value="${esc(editing ? editing.filename : '')}"${editing ? ' readonly' : ''}
            placeholder="main.lua" maxlength="100" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" required>
          <label for="content">โค้ด</label>
          <textarea class="input code" id="content" name="content" wrap="off" spellcheck="false" placeholder="วางโค้ด Lua ที่นี่" required>
${esc(editing ? editing.content : '')}</textarea>
          <div class="row">
            <button class="btn btn-primary grow">บันทึกโค้ด</button>
            ${editing ? `<a class="btn" href="${DASH}">ยกเลิก</a>` : ''}
          </div>
        </form>
      </section>

      <section class="panel" aria-labelledby="upload-title">
        <div class="panel-head">
          <h2 id="upload-title">อัปโหลดไฟล์</h2>
          <span class="sub">.lua หรือ .txt ไม่เกิน 10 MB</span>
        </div>
        <form class="panel-body" method="POST" action="/upload" enctype="multipart/form-data">
          ${csrfField}
          <input class="input" type="file" name="luaFile" accept=".lua,.txt" aria-label="เลือกไฟล์ที่จะอัปโหลด" required>
          <button class="btn btn-primary btn-block">อัปโหลดขึ้นระบบ</button>
        </form>
      </section>
    </div>
  </div>
</div>`, CLIENT_JS);
}

// =====================================================================
//  6) Routes: สาธารณะ
// =====================================================================
app.get('/', (req, res) => res.send(homeView()));

app.get('/blocked-image', (req, res) => {
    if (!BLOCK_IMG) return res.status(404).end();
    res.set('Cache-Control', 'public, max-age=3600');
    res.sendFile(BLOCK_IMG);
});

// ตัวโหลดเรียกเส้นทางนี้เพื่อขอคีย์สุ่มใหม่ทุกครั้งก่อนดึงสคริปต์จริง
app.get('/api/key/:filename', async (req, res) => {
    try {
        if (!KEY_SYSTEM) return res.status(404).json({ error: 'disabled' });
        if (GAME_ONLY && !req.session.loggedIn && looksLikeBrowser(req)) {
            return res.status(404).json({ error: 'not found' });
        }
        const name = req.params.filename;
        const device = str(req.query.device);
        if (name.length > 100 || !validDevice(device)) return res.status(400).json({ error: 'bad request' });

        const content = await getScript(name);
        if (content === null) return res.status(404).json({ error: 'not found' });

        const buf = Buffer.from(content, 'utf8');
        const key = genKey();
        await Key.create({ filename: name, device, key, expiresAt: new Date(Date.now() + KEY_TTL_MS) });

        res.set('Cache-Control', 'no-store').json({
            key, expiresIn: KEY_TTL_MS / 1000, len: buf.length, checksum: adler32(buf),
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'server error' });
    }
});

app.get('/raw/:filename', async (req, res) => {
    try {
        if (env.RAW_DEBUG === 'true') {
            console.log('RAW', req.params.filename, JSON.stringify({
                ua: req.get('user-agent'), accept: req.get('accept'),
                sfm: req.get('sec-fetch-mode'), sfd: req.get('sec-fetch-dest'),
            }));
        }
        if (GAME_ONLY && !req.session.loggedIn && looksLikeBrowser(req)) return deny(res);

        const name = req.params.filename;
        if (name.length > 100) return deny(res);

        if (KEY_SYSTEM && !req.session.loggedIn && !KEY_EXEMPT.has(name)) {
            const key = str(req.query.key);
            const device = str(req.query.device);
            if (!key || !validDevice(device)) return deny(res);
            // ใช้คีย์แบบ atomic: คีย์เดียวใช้ได้ครั้งเดียวแม้ยิงพร้อมกัน
            const claimed = await Key.findOneAndUpdate(
                { filename: name, key, device, used: false, expiresAt: { $gt: new Date() } },
                { used: true },
            );
            if (!claimed) return deny(res);
        }

        const content = await getScript(name);
        if (content === null) return deny(res);

        res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' });
        res.send(content);
    } catch (err) {
        console.error(err);
        res.status(500).type('text/plain').send('Server Error');
    }
});

// =====================================================================
//  7) Routes: ผู้ดูแล
// =====================================================================
app.get(ADMIN, (req, res) => {
    if (req.session.loggedIn) return res.redirect(DASH);
    const error = req.query.err === '2' ? 'ลองผิดหลายครั้งเกินไป กรุณารอ 15 นาที'
        : req.query.err ? 'รหัสผ่านไม่ถูกต้อง'
        : '';
    res.set('Cache-Control', 'no-store').send(loginView(error));
});

app.post('/login', (req, res) => {
    const { ip } = req;
    if (isLoginLocked(ip)) return res.redirect(`${ADMIN}?err=2`);
    if (!safeEqual(str(req.body.password), ADMIN_PASSWORD)) {
        recordLoginFail(ip);
        return res.redirect(`${ADMIN}?err=1`);
    }

    loginFails.delete(ip);
    req.session.regenerate(err => {
        if (err) return res.status(500).send('Server Error');
        req.session.loggedIn = true;
        req.session.csrf = crypto.randomBytes(24).toString('hex');
        req.session.save(() => res.redirect(DASH));
    });
});

app.get(DASH, async (req, res) => {
    if (!req.session.loggedIn) return res.redirect(ADMIN);
    try {
        const scripts = await Script.aggregate([
            { $project: { filename: 1, updatedAt: 1, size: { $strLenBytes: '$content' } } },
            { $sort: { filename: 1 } },
        ]);
        const editName = str(req.query.edit);
        const editing = editName ? await Script.findOne({ filename: editName }).lean() : null;

        res.set('Cache-Control', 'no-store').send(dashboardView({
            csrf: req.session.csrf,
            base: `${req.protocol}://${req.get('host')}`,
            scripts,
            editing,
            message: MESSAGES[str(req.query.m)],
        }));
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.post('/save', requireAuth, checkCsrf, async (req, res) => {
    try {
        const name = str(req.body.filename).trim();
        const content = normalizeNewlines(str(req.body.content));
        const isEdit = req.body.mode === 'edit';

        if (!content.trim()) return res.redirect(`${DASH}?m=empty`);
        if (isEdit) {
            if (!(await Script.exists({ filename: name }))) return res.redirect(`${DASH}?m=notfound`);
        } else {
            if (!validName(name)) return res.redirect(`${DASH}?m=badname`);
            if (await Script.exists({ filename: name })) return res.redirect(`${DASH}?m=exists`);
        }

        await saveScript(name, content);
        res.redirect(`${DASH}?m=saved`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving to database');
    }
});

// multer ต้องอ่าน multipart ก่อน ถึงจะตรวจ CSRF จาก body ได้
app.post('/upload', requireAuth, upload.single('luaFile'), checkCsrf, async (req, res) => {
    if (!req.file) return res.redirect(`${DASH}?m=nofile`);
    try {
        if (!/\.(lua|txt)$/i.test(req.file.originalname)) return res.redirect(`${DASH}?m=badext`);

        const name = cleanName(req.file.originalname);
        if (!validName(name)) return res.redirect(`${DASH}?m=badname`);

        const content = normalizeNewlines(req.file.buffer.toString('utf-8'));
        if (!content.trim()) return res.redirect(`${DASH}?m=empty`);

        await saveScript(name, content);
        res.redirect(`${DASH}?m=uploaded`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving to database');
    }
});

app.post('/delete', requireAuth, checkCsrf, async (req, res) => {
    try {
        const name = str(req.body.filename);
        await Script.deleteOne({ filename: name });
        scriptCache.delete(name);
        res.redirect(`${DASH}?m=deleted`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting from database');
    }
});

app.post('/logout', checkCsrf, (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// =====================================================================
//  8) Error handler + Start
// =====================================================================
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err instanceof multer.MulterError) return res.redirect(`${DASH}?m=toolarge`);
    if (err.type === 'entity.too.large') {
        return req.path === '/save'
            ? res.redirect(`${DASH}?m=toolarge`)
            : res.status(413).type('text/plain').send('Payload too large');
    }
    console.error(err);
    res.status(500).send('Server Error');
});

mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB Atlas');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });
