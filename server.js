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
    if (over('all:' + ip, RL_ALL) || (req.path.startsWith('/raw/') && over('raw:' + ip, RL_RAW))) {
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
:root{--bg:#0a0a0a;--panel:rgba(255,255,255,.045);--line:rgba(255,255,255,.15);--ac:#ffffff;--red:#ff5a5a;--mut:#8c8c8c;--ink:#ededed}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.6 'Segoe UI',Tahoma,'Noto Sans Thai',sans-serif;padding:20px;position:relative}
body::before{content:'';position:fixed;inset:0;z-index:-2;background:radial-gradient(620px 420px at 12% -5%,rgba(255,255,255,.09),transparent 70%),radial-gradient(620px 420px at 100% 100%,rgba(255,255,255,.06),transparent 70%)}
body::after{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px);background-size:42px 42px;-webkit-mask-image:radial-gradient(ellipse at center,#000 25%,transparent 78%);mask-image:radial-gradient(ellipse at center,#000 25%,transparent 78%)}
.wrap{max-width:680px;margin:0 auto}
h1,h2{font-family:Orbitron,'Segoe UI','Noto Sans Thai',sans-serif;letter-spacing:.06em;margin:0 0 4px}
h2{color:#fff;font-size:22px;text-shadow:0 0 14px rgba(255,255,255,.3)}
h3{display:flex;align-items:center;gap:12px;color:var(--ink);font-size:17px;margin:36px 0 14px}
h3::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
.sub{color:var(--mut);font-size:14px}
.hero{text-align:center}
.eyebrow{color:var(--mut);font:600 13px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.3em;margin-bottom:10px}
.hero-title{font-size:clamp(40px,12vw,76px);font-weight:800;line-height:1.1;background:linear-gradient(180deg,#ffffff,#8a8a8a);-webkit-background-clip:text;background-clip:text;color:transparent;filter:drop-shadow(0 0 14px rgba(255,255,255,.22))}
input[type=text],input[type=password],input[type=search],textarea{width:100%;padding:12px 14px;background:rgba(0,0,0,.6);border:1px solid rgba(255,255,255,.2);border-radius:8px;color:var(--ink);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;outline:none;margin-bottom:12px;transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus{border-color:#fff;box-shadow:0 0 0 3px rgba(255,255,255,.12)}
input[readonly]{opacity:.65}
textarea{resize:vertical;min-height:180px}
.b{display:inline-block;padding:7px 13px;border:1px solid var(--line);border-radius:8px;background:rgba(255,255,255,.04);color:var(--ink);font:inherit;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer;transition:border-color .15s,background .15s,color .15s}
.b:hover{border-color:#fff;background:rgba(255,255,255,.1);color:#fff}
.b-ac{background:#fff;border-color:#fff;color:#000}
.b-ac:hover{background:#dcdcdc;border-color:#dcdcdc;color:#000}
.b-red{color:var(--red);border-color:rgba(255,90,90,.5);background:transparent}
.b-red:hover{color:var(--red);border-color:var(--red);background:rgba(255,90,90,.1)}
.b-lg{padding:12px 20px;font-size:15px;border-radius:10px}
.b-full{display:block;width:100%;text-align:center}
ul{list-style:none;padding:0;margin:0}
.item{background:var(--panel);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);border:1px solid var(--line);border-left:3px solid #fff;border-radius:10px;padding:12px 14px;margin-bottom:10px;transition:border-color .15s,background .15s}
.item:hover{border-color:rgba(255,255,255,.35);background:rgba(255,255,255,.07)}
.fn{font-family:ui-monospace,Menlo,Consolas,monospace;color:#fff;word-break:break-all}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.actions form{margin:0}
.card{background:var(--panel);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.25);border-radius:16px;padding:28px;box-shadow:0 0 34px rgba(255,255,255,.06)}
.login{width:100%;max-width:360px;text-align:center}
.login h2{margin-bottom:6px}
.login form{margin-top:20px}
.lock{font-size:34px;margin-bottom:6px;filter:grayscale(1) brightness(1.6)}
.toast{padding:10px 14px;border-radius:10px;margin:14px 0;font-weight:600}
.toast.ok{background:rgba(255,255,255,.08);color:#fff;border:1px solid rgba(255,255,255,.6)}
.toast.err{background:rgba(255,90,90,.09);color:var(--red);border:1px solid var(--red)}
.drop{background:rgba(0,0,0,.45);border:1px dashed rgba(255,255,255,.3);padding:18px;border-radius:10px;text-align:center;color:var(--mut);margin-bottom:12px}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.center{display:flex;justify-content:center;align-items:center;min-height:90vh}
.badge{display:inline-flex;align-items:center;gap:9px;background:rgba(255,255,255,.06);color:#fff;padding:6px 18px;border-radius:999px;border:1px solid rgba(255,255,255,.5);font-size:14px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#fff;animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

const page = (title, body, script = '') => `<!DOCTYPE html>
<html lang="th"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&display=swap" rel="stylesheet">
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
    document.querySelectorAll('.item').forEach(function(li){li.hidden=!!v&&li.getAttribute('data-name').indexOf(v)<0});
  });
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
        <div class="center"><div class="hero">
            <div class="eyebrow">// RAW SCRIPT SERVER</div>
            <h1 class="hero-title">VOID HUB</h1>
            <p class="sub">ระบบโฮสต์สคริปต์ออนไลน์</p>
            <div style="margin-top:36px"><span class="badge"><span class="dot"></span>ระบบออนไลน์</span></div>
        </div></div>`));
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
<style>html,body{margin:0;height:100%;background:#111;display:flex;align-items:center;justify-content:center}
img{max-width:100%;max-height:100vh}p{color:#ccc;font:20px sans-serif}</style></head>
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
    const err = req.query.err === '2' ? 'ลองผิดหลายครั้งเกินไป กรุณารอ 15 นาที'
              : req.query.err ? 'รหัสผ่านไม่ถูกต้อง' : '';
    res.set('Cache-Control', 'no-store').send(page('Admin Login', `
        <div class="center"><div class="card login">
            <div class="lock">🔐</div>
            <h2>ADMIN ACCESS</h2>
            <p class="sub">กรอกรหัสผ่านเพื่อเข้าสู่ระบบ</p>
            ${err ? `<div class="toast err">${esc(err)}</div>` : ''}
            <form method="POST" action="/login">
                <input type="password" name="password" placeholder="รหัสผ่าน" autocomplete="current-password" autofocus required>
                <button class="b b-ac b-lg b-full">เข้าสู่ระบบ</button>
            </form>
        </div></div>`));
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
            const snippet = `loadstring(game:HttpGet("${url}"))()`;
            return `
            <li class="item" data-name="${esc(s.filename.toLowerCase())}">
                <div class="fn">📄 ${esc(s.filename)}</div>
                <div class="sub">${fmtSize(s.size)}${s.updatedAt ? ' · ' + esc(fmtDate(s.updatedAt)) : ''}</div>
                <div class="actions">
                    <button type="button" class="b b-ac" data-copy="${esc(url)}">คัดลอกลิงก์</button>
                    <button type="button" class="b" data-copy="${esc(snippet)}">loadstring</button>
                    <a class="b" href="${esc(url)}" target="_blank" rel="noopener">Raw</a>
                    <a class="b" href="?edit=${encodeURIComponent(s.filename)}#editor">แก้ไข</a>
                    <form method="POST" action="/delete" data-msg="ลบไฟล์ ${esc(s.filename)} ออกจากระบบ?" onsubmit="return confirm(this.dataset.msg)">
                        ${csrf}<input type="hidden" name="filename" value="${esc(s.filename)}">
                        <button class="b b-red">ลบ</button>
                    </form>
                </div>
            </li>`;
        }).join('');

        const [type, text] = MESSAGES[str(req.query.m)] || [];

        res.set('Cache-Control', 'no-store').send(page('Void Hub - Dashboard', `
        <div class="wrap">
            <div class="top">
                <div><h2>VOID HUB</h2><div class="sub"><span class="dot"></span> DASHBOARD · ไฟล์ทั้งหมด ${scripts.length} รายการ</div></div>
                <form method="POST" action="/logout" style="margin:0">${csrf}<button class="b b-red">ออกจากระบบ</button></form>
            </div>
            ${text ? `<div class="toast ${type}">${esc(text)}</div>` : ''}

            <h3>📜 รายการไฟล์ในระบบ</h3>
            ${scripts.length > 4 ? '<input type="search" id="q" placeholder="ค้นหาชื่อไฟล์...">' : ''}
            <ul>${list || '<li class="sub" style="text-align:center;padding:20px">ยังไม่มีไฟล์ในระบบ</li>'}</ul>

            <h3 id="editor">${editing ? '✏️ แก้ไข: ' + esc(editing.filename) : '✍️ สร้างไฟล์ใหม่'}</h3>
            <form method="POST" action="/save">
                ${csrf}<input type="hidden" name="mode" value="${editing ? 'edit' : 'new'}">
                <input type="text" name="filename" value="${esc(editing ? editing.filename : '')}" ${editing ? 'readonly' : ''}
                    placeholder="ชื่อไฟล์ เช่น main.lua" maxlength="100" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" required>
                <textarea name="content" spellcheck="false" placeholder="วางโค้ด Lua ที่นี่..." required>
${esc(editing ? editing.content : '')}</textarea>
                <div class="actions" style="margin-top:0">
                    <button class="b b-ac b-lg" style="flex:1">💾 บันทึกโค้ด</button>
                    ${editing ? `<a class="b b-lg" href="${DASH}">ยกเลิก</a>` : ''}
                </div>
            </form>

            <h3>📁 อัปโหลดไฟล์ (.lua / .txt)</h3>
            <form method="POST" action="/upload" enctype="multipart/form-data">
                ${csrf}
                <div class="drop"><input type="file" name="luaFile" accept=".lua,.txt" required></div>
                <button class="b b-lg b-full">⬆️ อัปโหลดไฟล์ขึ้นระบบ</button>
            </form>
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
