require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ================= ตั้งค่า =================
const { MONGODB_URI, ADMIN_PASSWORD } = process.env;
const SECRET_ADMIN_PATH = process.env.SECRET_ADMIN_PATH || 'void-admin-9988';
const PORT = process.env.PORT || 3000;
// true = ลิงก์ Raw ไม่ตอบเบราว์เซอร์ (ยกเว้นแอดมินที่ล็อกอินอยู่) ปิดได้ด้วย RAW_GAME_ONLY=false
const GAME_ONLY = process.env.RAW_GAME_ONLY !== 'false';
const ADMIN = `/${SECRET_ADMIN_PATH}`;
const DASH = `${ADMIN}/dashboard`;

if (!MONGODB_URI || !ADMIN_PASSWORD) {
    console.error('❌ ต้องตั้งค่า MONGODB_URI และ ADMIN_PASSWORD ใน Environment variables');
    process.exit(1);
}
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️ ไม่ได้ตั้ง SESSION_SECRET (สุ่มให้ชั่วคราว ล็อกอินจะหลุดเมื่อเซิร์ฟเวอร์รีสตาร์ต)');
}

// ================= Middleware =================
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ================= กันยิงถี่ (rate limit + แบนชั่วคราว) =================
// ปรับได้ด้วย Environment variables: RATE_LIMIT_RAW, RATE_LIMIT_ALL, RATE_BAN_MINUTES
const RL_RAW = Number(process.env.RATE_LIMIT_RAW) || 60;    // ลิงก์ /raw ต่อนาทีต่อ IP
const RL_ALL = Number(process.env.RATE_LIMIT_ALL) || 240;   // ทุกเส้นทางรวมกันต่อนาทีต่อ IP
const BAN_MS = (Number(process.env.RATE_BAN_MINUTES) || 5) * 60 * 1000;
const hits = new Map();    // key -> { n, reset }
const banned = new Map();  // ip -> เวลาที่หมดแบน
const over = (key, limit) => {
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset <= now) { h = { n: 0, reset: now + 60 * 1000 }; hits.set(key, h); }
    return ++h.n > limit;
};
app.use((req, res, next) => {
    const ip = req.ip, now = Date.now();
    const until = banned.get(ip);
    if (until && until > now) {
        res.set('Retry-After', String(Math.ceil((until - now) / 1000)));
        return res.status(429).type('text/plain').send('Too many requests');
    }
    if (over('all:' + ip, RL_ALL)
        || (req.path.startsWith('/raw/') && over('raw:' + ip, RL_RAW))) {
        banned.set(ip, now + BAN_MS);
        res.set('Retry-After', String(Math.ceil(BAN_MS / 1000)));
        return res.status(429).type('text/plain').send('Too many requests');
    }
    next();
});
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
    for (const [k, v] of banned) if (v <= now) banned.delete(k);
}, 60 * 1000).unref();
app.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
    });
    next();
});

// เก็บ session ลง MongoDB ถ้าติดตั้ง connect-mongo ไว้ (npm i connect-mongo) ไม่งั้นใช้ memory
let store;
try {
    const MS = require('connect-mongo');
    store = (MS.default || MS).create({ mongoUrl: MONGODB_URI });
    console.log('🗄️ Session store: MongoDB');
} catch (e) {
    if (e.code !== 'MODULE_NOT_FOUND') throw e;
    console.log('ℹ️ Session store: memory (ติดตั้ง connect-mongo เพื่อไม่ให้ล็อกอินหลุดตอนรีสตาร์ต)');
}

app.use(session({
    name: 'vh.sid',
    secret: SESSION_SECRET,
    store,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: 'auto' },
}));

// อ่าน body: /save รับก้อนใหญ่ได้ แต่เฉพาะแอดมินที่ล็อกอิน ส่วนที่เหลือจำกัด 100 KB กันคนส่งข้อมูลก้อนใหญ่มาถล่ม
app.use('/save',
    (req, res, next) => (req.session.loggedIn ? next() : res.status(403).send('Access Denied')),
    express.urlencoded({ limit: '10mb', extended: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ limit: '100kb', extended: false }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ================= Database =================
const Script = mongoose.model('Script', new mongoose.Schema({
    filename: { type: String, required: true, unique: true, trim: true },
    content: { type: String, required: true },
}, { timestamps: true }));

// แคชเนื้อสคริปต์ไว้ในหน่วยความจำ 30 วินาที (รวมชื่อที่ไม่มีอยู่) ลดภาระฐานข้อมูลเวลาโดนยิงถี่
const rawCache = new Map();
const CACHE_TTL = 30 * 1000, CACHE_MAX = 500;
async function getScript(name) {
    const c = rawCache.get(name);
    if (c && c.exp > Date.now()) return c.content;
    const s = await Script.findOne({ filename: name }, 'content').lean();
    const content = s ? s.content : null;
    if (rawCache.size >= CACHE_MAX) rawCache.clear();
    rawCache.set(name, { content, exp: Date.now() + CACHE_TTL });
    return content;
}

// ================= Helpers =================
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const str = v => (typeof v === 'string' ? v : '');
const validName = n => /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(n);
const cleanName = n => str(n).trim().replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._-]+/, '').slice(0, 100);
const fmtSize = n => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const fmtDate = d => new Date(d).toLocaleString('th-TH', { timeZone: 'Asia/Bangkok', dateStyle: 'medium', timeStyle: 'short' });
const safeEq = (a, b) => crypto.timingSafeEqual(
    crypto.createHash('sha256').update(String(a)).digest(),
    crypto.createHash('sha256').update(String(b)).digest()
);

// จำกัดการเดารหัสผ่าน: ผิด 5 ครั้งต่อ IP แล้วล็อก 15 นาที
const attempts = new Map();
const WINDOW = 15 * 60 * 1000;
const tooMany = ip => { const a = attempts.get(ip); return !!a && a.reset > Date.now() && a.n >= 5; };
const addFail = ip => {
    let a = attempts.get(ip);
    if (!a || a.reset <= Date.now()) { a = { n: 0, reset: Date.now() + WINDOW }; attempts.set(ip, a); }
    a.n++;
};
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (v.reset <= now) attempts.delete(k); }, WINDOW).unref();

const requireAuth = (req, res, next) => (req.session.loggedIn ? next() : res.status(403).send('Access Denied'));
const checkCsrf = (req, res, next) => {
    const t = str(req.body && req.body._csrf);
    if (!req.session.csrf || !safeEq(t, req.session.csrf)) return res.status(403).send('Invalid CSRF token');
    next();
};

// ================= หน้าเว็บ (UI) =================
const CSS = `
:root{--bg:#1a1727;--surface:#231f33;--raised:#2c2740;--line:#3d3757;--ink:#ece9f6;--mut:#a29cbd;--ac:#9b8cff;--ac-ink:#17122e;--red:#f0687f;--ok:#62d6a6;
--mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;--sans:'IBM Plex Sans Thai','Segoe UI',Tahoma,sans-serif}
*{box-sizing:border-box}
html{background:var(--bg);color-scheme:dark}
body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.65 var(--sans);-webkit-font-smoothing:antialiased}
:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
h1,h2{margin:0;font-weight:600}
.meta,.sub{color:var(--mut);font-size:14px}
.sub{margin:0}

/* ---------- ปุ่ม / ฟอร์ม ---------- */
.b{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 16px;border:1px solid var(--line);border-radius:10px;background:var(--raised);color:var(--ink);font:500 15px/1.2 var(--sans);text-decoration:none;cursor:pointer;transition:background .15s,border-color .15s}
.b:hover{border-color:var(--mut)}
.b-sm{padding:6px 11px;font-size:13px;border-radius:8px}
.b-ac{background:var(--ac);border-color:var(--ac);color:var(--ac-ink);font-weight:600}
.b-ac:hover{background:#b3a8ff;border-color:#b3a8ff}
.b-ghost{background:transparent}
.b-red{background:transparent;color:var(--red);border-color:rgba(240,104,127,.45)}
.b-red:hover{background:rgba(240,104,127,.12);border-color:var(--red)}
.b-full{display:flex;width:100%}
.lbl{display:block;margin:0 0 6px;color:var(--mut);font-size:14px}
input[type=text],input[type=password],input[type=search],textarea{width:100%;padding:11px 13px;background:var(--bg);border:1px solid var(--line);border-radius:10px;color:var(--ink);font:14px/1.6 var(--mono);outline:none;margin-bottom:14px;transition:border-color .15s}
input[type=password]{font-family:var(--sans);font-size:16px}
input:focus,textarea:focus{border-color:var(--ac)}
input[readonly]{opacity:.6}
textarea{min-height:340px;resize:vertical;white-space:pre;overflow:auto;tab-size:4}
::placeholder{color:#6f6990}

/* ---------- ตราโลโก้ ---------- */
.mark{display:inline-block;width:24px;height:24px;border-radius:50%;flex:none;background:radial-gradient(circle,var(--bg) 0 48%,transparent 50%),conic-gradient(from 200deg,#9b8cff,#5b8cff,#c77dff,#9b8cff)}

/* ---------- หน้าแรก / บล็อก / ล็อกอิน ---------- */
.center{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
.hero{display:grid;justify-items:center;gap:16px;text-align:center}
.stage{position:relative;display:grid;place-items:center;width:min(78vw,400px);aspect-ratio:1}
.orb{position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle,#0e0c17 0 62%,transparent 64%),conic-gradient(from 0deg,#9b8cff,#5b8cff,#c77dff,#9b8cff);box-shadow:0 0 100px rgba(155,140,255,.25);animation:spin 36s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hero-title{position:relative;font-size:clamp(44px,13vw,80px);font-weight:700;line-height:1.02;letter-spacing:.06em}
.badge{display:inline-flex;align-items:center;gap:9px;padding:6px 16px;border-radius:999px;border:1px solid var(--line);background:var(--surface);font-size:14px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok)}
.card{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:30px 26px}
.card .mark{width:40px;height:40px;margin-bottom:14px}
.card h1{font-size:22px;margin-bottom:4px}
.card form{margin-top:22px}
.card input{margin-bottom:12px}
.denied{text-align:center;color:var(--mut)}

/* ---------- แดชบอร์ด ---------- */
.shell{max-width:1120px;margin:0 auto;padding:20px}
.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:4px 0 22px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px;letter-spacing:.06em}
.brand .meta{font-weight:400;letter-spacing:0;padding-left:10px;border-left:1px solid var(--line)}
.grid{display:grid;grid-template-columns:minmax(280px,360px) 1fr;gap:20px;align-items:start}
.stack{display:grid;gap:20px;min-width:0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px;min-width:0}
.panel-h{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 16px;border-bottom:1px solid var(--line)}
.panel-h h2{font-size:16px;display:flex;align-items:center;gap:8px;word-break:break-all}
.panel-b{padding:16px}
.count{padding:0 9px;border-radius:999px;background:var(--raised);color:var(--mut);font-size:13px;font-weight:500}
.search{padding:12px 12px 0}
.search input{margin:0}
.files{list-style:none;margin:0;padding:8px;max-height:72vh;overflow:auto}
.file{padding:11px 12px;border:1px solid transparent;border-radius:10px;margin-bottom:4px}
.file:hover{background:var(--raised)}
.file.on{background:var(--raised);border-color:var(--ac)}
.fn{font:14px/1.5 var(--mono);word-break:break-all}
.actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.actions form{margin:0}
.empty{padding:26px 16px;text-align:center;color:var(--mut);font-size:14px}
.foot{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.foot .actions{margin:0}
.drop{padding:18px;margin-bottom:14px;border:1px dashed var(--line);border-radius:10px;background:var(--bg);color:var(--mut);font-size:14px}
.drop input{width:100%;color:var(--mut)}
.toast{padding:11px 14px;border-radius:10px;margin:0 0 18px;font-weight:500;border:1px solid;transition:opacity .6s}
.toast.ok{background:rgba(98,214,166,.1);border-color:rgba(98,214,166,.5);color:var(--ok)}
.toast.err{background:rgba(240,104,127,.1);border-color:rgba(240,104,127,.5);color:var(--red)}
@media (max-width:860px){.grid{grid-template-columns:1fr}.files{max-height:none}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

const page = (title, body, script = '') => `<!DOCTYPE html>
<html lang="th"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Thai:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>${CSS}</style></head>
<body>${body}${script ? `<script>${script}</script>` : ''}</body></html>`;

const CLIENT_JS = `
(function(){
  function copy(t,b){
    var o=b.textContent;
    function ok(){b.textContent='คัดลอกแล้ว ✓';setTimeout(function(){b.textContent=o},1200)}
    function fb(){var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(x)}
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,fb)}else{fb()}
  }
  document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(b)copy(b.getAttribute('data-copy'),b)});
  var q=document.getElementById('q');
  if(q)q.addEventListener('input',function(){
    var v=q.value.trim().toLowerCase();
    document.querySelectorAll('.file').forEach(function(li){li.hidden=!!v&&li.getAttribute('data-name').indexOf(v)<0});
  });
  var ta=document.getElementById('ta'),cnt=document.getElementById('cnt');
  function upd(){if(ta&&cnt){var v=ta.value;cnt.textContent=(v?v.split('\\n').length:0)+' บรรทัด · '+v.length+' ตัวอักษร'}}
  if(ta){
    upd();ta.addEventListener('input',upd);
    ta.addEventListener('keydown',function(e){
      if(e.key==='Tab'&&!e.shiftKey){e.preventDefault();var s=ta.selectionStart;ta.setRangeText('\\t',s,ta.selectionEnd,'end');upd()}
    });
  }
  var t=document.querySelector('.toast');
  if(t)setTimeout(function(){t.style.opacity='0'},4000);
  if(location.search.indexOf('m=')>-1)history.replaceState(null,'',location.pathname);
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

// ================= Routes: สาธารณะ =================
app.get('/', (req, res) => {
    res.send(page('VOID HUB', `
        <main class="center"><div class="hero">
            <div class="stage">
                <div class="orb" aria-hidden="true"></div>
                <h1 class="hero-title">VOID<br>HUB</h1>
            </div>
            <p class="sub">ระบบโฮสต์สคริปต์ออนไลน์</p>
            <span class="badge"><span class="dot"></span>ระบบพร้อมใช้งาน</span>
        </div></main>`));
});

// หน้าที่แสดงเมื่อถูกบล็อก / ไม่พบไฟล์ (ใช้แบบเดียวกันทั้งสองกรณี คนนอกจะเดาไม่ได้ว่ามีไฟล์จริงไหม)
// ใส่รูปโดยวางไฟล์ block.png (หรือ .jpg .jpeg .gif .webp) ไว้โฟลเดอร์เดียวกับ server.js
const BLOCK_IMG = ['png', 'jpg', 'jpeg', 'gif', 'webp']
    .map(e => path.join(__dirname, `block.${e}`))
    .find(f => fs.existsSync(f));
const BLOCK_TEXT = process.env.BLOCK_TEXT || 'ดูอะไร นะ Error';

app.get('/blocked-image', (req, res) => {
    if (!BLOCK_IMG) return res.status(404).end();
    res.set('Cache-Control', 'public, max-age=3600');
    res.sendFile(BLOCK_IMG);
});

const deny = res => {
    res.status(404).set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Error</title>
<style>html,body{margin:0;height:100%;background:#1a1727;display:flex;align-items:center;justify-content:center}
img{max-width:100%;max-height:100vh}p{color:#a29cbd;font:20px 'IBM Plex Sans Thai','Segoe UI',Tahoma,sans-serif;padding:20px;text-align:center}</style></head>
<body>${BLOCK_IMG ? '<img src="/blocked-image" alt="">' : `<p>${esc(BLOCK_TEXT)}</p>`}</body></html>`);
};

// ตรวจว่าเป็น "การเปิดหน้าเว็บของเบราว์เซอร์" จริงๆ จากหัวที่เบราว์เซอร์ส่งเฉพาะตอนเปิดหน้า
// (ไม่ดู User-Agent เพราะ executor บางตัวใช้ Mozilla/... เหมือนกัน)
const looksLikeBrowser = req => {
    const accept = str(req.get('accept')).toLowerCase();
    return accept.includes('text/html')
        || req.get('sec-fetch-mode') === 'navigate'
        || req.get('sec-fetch-dest') === 'document'
        || !!req.get('upgrade-insecure-requests');
};

app.get('/raw/:filename', async (req, res) => {
    try {
        if (process.env.RAW_DEBUG === 'true') {
            console.log('RAW', req.params.filename, JSON.stringify({ ua: req.get('user-agent'), accept: req.get('accept'), sfm: req.get('sec-fetch-mode'), sfd: req.get('sec-fetch-dest') }));
        }
        if (GAME_ONLY && !req.session.loggedIn && looksLikeBrowser(req)) {
            return deny(res);
        }
        const name = req.params.filename;
        if (name.length > 100) return deny(res);

        const content = await getScript(name);
        if (content === null) return deny(res);
        res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' });
        res.send(content);
    } catch (err) {
        console.error(err);
        res.status(500).type('text/plain').send('Server Error');
    }
});

// ================= Routes: ผู้ดูแล =================
app.get(ADMIN, (req, res) => {
    if (req.session.loggedIn) return res.redirect(DASH);
    const err = req.query.err === '2' ? 'ลองผิดหลายครั้งเกินไป กรุณารอ 15 นาทีแล้วลองใหม่'
              : req.query.err ? 'รหัสผ่านไม่ถูกต้อง ลองใหม่อีกครั้ง' : '';
    res.set('Cache-Control', 'no-store').send(page('เข้าสู่ระบบแอดมิน', `
        <main class="center"><div class="card">
            <span class="mark" aria-hidden="true"></span>
            <h1>เข้าสู่ระบบแอดมิน</h1>
            <p class="sub">กรอกรหัสผ่านเพื่อจัดการสคริปต์</p>
            <form method="POST" action="/login">
                ${err ? `<div class="toast err" role="alert">${esc(err)}</div>` : ''}
                <label class="lbl" for="pw">รหัสผ่าน</label>
                <input type="password" id="pw" name="password" autocomplete="current-password" autofocus required>
                <button class="b b-ac b-full">เข้าสู่ระบบ</button>
            </form>
        </div></main>`));
});

app.post('/login', (req, res) => {
    const ip = req.ip;
    if (tooMany(ip)) return res.redirect(`${ADMIN}?err=2`);
    if (!safeEq(str(req.body.password), ADMIN_PASSWORD)) {
        addFail(ip);
        return res.redirect(`${ADMIN}?err=1`);
    }
    attempts.delete(ip);
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
        const csrf = `<input type="hidden" name="_csrf" value="${esc(req.session.csrf)}">`;
        const base = `${req.protocol}://${req.get('host')}`;

        const scripts = await Script.aggregate([
            { $project: { filename: 1, updatedAt: 1, size: { $strLenBytes: '$content' } } },
            { $sort: { filename: 1 } },
        ]);
        const editName = str(req.query.edit);
        const editing = editName ? await Script.findOne({ filename: editName }).lean() : null;

        const list = scripts.map(s => {
            const url = `${base}/raw/${encodeURIComponent(s.filename)}`;
            const loader = `loadstring(game:HttpGet("${url}"))()`;
            const on = editing && editing.filename === s.filename;
            return `
            <li class="file${on ? ' on' : ''}" data-name="${esc(s.filename.toLowerCase())}">
                <div class="fn">${esc(s.filename)}</div>
                <div class="meta">${fmtSize(s.size)}${s.updatedAt ? ' · ' + esc(fmtDate(s.updatedAt)) : ''}</div>
                <div class="actions">
                    <button type="button" class="b b-sm b-ac" data-copy="${esc(url)}">คัดลอกลิงก์</button>
                    <button type="button" class="b b-sm" data-copy="${esc(loader)}">คัดลอกตัวโหลด</button>
                    <a class="b b-sm" href="${esc(url)}" target="_blank" rel="noopener">Raw</a>
                    <a class="b b-sm" href="?edit=${encodeURIComponent(s.filename)}#editor">แก้ไข</a>
                    <form method="POST" action="/delete" data-msg="ลบไฟล์ ${esc(s.filename)} ออกจากระบบ?" onsubmit="return confirm(this.dataset.msg)">
                        ${csrf}<input type="hidden" name="filename" value="${esc(s.filename)}">
                        <button class="b b-sm b-red">ลบ</button>
                    </form>
                </div>
            </li>`;
        }).join('');

        const [type, text] = MESSAGES[str(req.query.m)] || [];

        res.set('Cache-Control', 'no-store').send(page('Void Hub - แดชบอร์ด', `
        <div class="shell">
            <header class="bar">
                <div class="brand"><span class="mark" aria-hidden="true"></span>VOID HUB<span class="meta">แดชบอร์ด</span></div>
                <form method="POST" action="/logout" style="margin:0">${csrf}<button class="b b-ghost">ออกจากระบบ</button></form>
            </header>
            ${text ? `<div class="toast ${type}" role="status">${esc(text)}</div>` : ''}

            <div class="grid">
                <section class="panel">
                    <div class="panel-h">
                        <h2>ไฟล์ในระบบ <span class="count">${scripts.length}</span></h2>
                        <a class="b b-sm b-ac" href="${DASH}#editor">+ ไฟล์ใหม่</a>
                    </div>
                    ${scripts.length ? '<div class="search"><input type="search" id="q" placeholder="ค้นหาชื่อไฟล์" aria-label="ค้นหาชื่อไฟล์"></div>' : ''}
                    <ul class="files">${list || '<li class="empty">ยังไม่มีไฟล์ในระบบ เริ่มจากสร้างไฟล์แรกหรืออัปโหลดได้เลย</li>'}</ul>
                </section>

                <div class="stack">
                    <section class="panel" id="editor">
                        <div class="panel-h"><h2>${editing ? 'แก้ไข ' + esc(editing.filename) : 'สร้างไฟล์ใหม่'}</h2></div>
                        <form method="POST" action="/save" class="panel-b">
                            ${csrf}<input type="hidden" name="mode" value="${editing ? 'edit' : 'new'}">
                            <label class="lbl" for="fname">ชื่อไฟล์</label>
                            <input type="text" id="fname" name="filename" value="${esc(editing ? editing.filename : '')}" ${editing ? 'readonly' : ''}
                                placeholder="เช่น main.lua" maxlength="100" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" required>
                            <label class="lbl" for="ta">โค้ด</label>
                            <textarea id="ta" name="content" wrap="off" spellcheck="false" placeholder="วางโค้ด Lua ที่นี่" required>
${esc(editing ? editing.content : '')}</textarea>
                            <div class="foot">
                                <span class="meta" id="cnt"></span>
                                <div class="actions">
                                    ${editing ? `<a class="b" href="${DASH}">ยกเลิก</a>` : ''}
                                    <button class="b b-ac">บันทึกโค้ด</button>
                                </div>
                            </div>
                        </form>
                    </section>

                    <section class="panel">
                        <div class="panel-h"><h2>อัปโหลดไฟล์</h2><span class="meta">.lua หรือ .txt · ไม่เกิน 10 MB</span></div>
                        <form method="POST" action="/upload" enctype="multipart/form-data" class="panel-b">
                            ${csrf}
                            <div class="drop"><input type="file" name="luaFile" accept=".lua,.txt" required></div>
                            <button class="b b-full">อัปโหลดขึ้นระบบ</button>
                        </form>
                    </section>
                </div>
            </div>
        </div>`, CLIENT_JS));
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

app.post('/save', requireAuth, checkCsrf, async (req, res) => {
    try {
        const name = str(req.body.filename).trim();
        const content = str(req.body.content).replace(/\r\n/g, '\n');
        const editMode = req.body.mode === 'edit';
        if (!content.trim()) return res.redirect(`${DASH}?m=empty`);
        if (editMode) {
            if (!(await Script.exists({ filename: name }))) return res.redirect(`${DASH}?m=notfound`);
        } else {
            if (!validName(name)) return res.redirect(`${DASH}?m=badname`);
            if (await Script.exists({ filename: name })) return res.redirect(`${DASH}?m=exists`);
        }
        await Script.findOneAndUpdate({ filename: name }, { content }, { upsert: true });
        rawCache.delete(name);
        res.redirect(`${DASH}?m=saved`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving to database');
    }
});

app.post('/upload', requireAuth, upload.single('luaFile'), checkCsrf, async (req, res) => {
    if (!req.file) return res.redirect(`${DASH}?m=nofile`);
    try {
        if (!/\.(lua|txt)$/i.test(req.file.originalname)) return res.redirect(`${DASH}?m=badext`);
        const name = cleanName(req.file.originalname);
        if (!validName(name)) return res.redirect(`${DASH}?m=badname`);
        const content = req.file.buffer.toString('utf-8').replace(/\r\n/g, '\n');
        if (!content.trim()) return res.redirect(`${DASH}?m=empty`);
        await Script.findOneAndUpdate({ filename: name }, { content }, { upsert: true });
        rawCache.delete(name);
        res.redirect(`${DASH}?m=uploaded`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving to database');
    }
});

app.post('/delete', requireAuth, checkCsrf, async (req, res) => {
    try {
        const delName = str(req.body.filename);
        await Script.deleteOne({ filename: delName });
        rawCache.delete(delName);
        res.redirect(`${DASH}?m=deleted`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting from database');
    }
});

app.post('/logout', checkCsrf, (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ================= Error handler =================
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) return res.redirect(`${DASH}?m=toolarge`);
    if (err.type === 'entity.too.large') return req.path === '/save' ? res.redirect(`${DASH}?m=toolarge`) : res.status(413).type('text/plain').send('Payload too large');
    console.error(err);
    res.status(500).send('Server Error');
});

// ================= Start =================
mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB Atlas');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });
