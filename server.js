require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');

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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: false }));
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

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ================= Database =================
const Script = mongoose.model('Script', new mongoose.Schema({
    filename: { type: String, required: true, unique: true, trim: true },
    content: { type: String, required: true },
}, { timestamps: true }));

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
:root{--bg:#0a0a0a;--card:#15151a;--line:#2a2a33;--ac:#00ffcc;--red:#ff4444;--mut:#8a8a96;--ink:#f2f2f5}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 'Segoe UI',Tahoma,'Noto Sans Thai',sans-serif;padding:20px}
.wrap{max-width:680px;margin:0 auto}
h1,h2{color:var(--ac);text-shadow:0 0 10px rgba(0,255,204,.3);margin:0 0 4px}
h3{color:#ccc;border-bottom:1px solid var(--line);padding-bottom:10px;margin:32px 0 14px}
.sub{color:var(--mut);font-size:14px}
input[type=text],input[type=password],input[type=search],textarea{width:100%;padding:12px;background:var(--card);border:1px solid #444;border-radius:8px;color:var(--ink);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;outline:none;margin-bottom:12px}
input:focus,textarea:focus{border-color:var(--ac)}
input[readonly]{opacity:.7}
textarea{resize:vertical;min-height:180px}
.b{display:inline-block;padding:7px 13px;border:1px solid var(--line);border-radius:6px;background:#1d1d24;color:var(--ink);font:inherit;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer}
.b:hover{border-color:var(--ac)}
.b-ac{background:var(--ac);border-color:var(--ac);color:#000}
.b-red{color:var(--red);border-color:var(--red);background:transparent}
.b-lg{padding:12px 20px;font-size:15px;border-radius:8px}
.b-full{display:block;width:100%;text-align:center}
ul{list-style:none;padding:0;margin:0}
.item{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--ac);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.fn{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--ac);word-break:break-all}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.actions form{margin:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;box-shadow:0 0 20px rgba(0,255,204,.08)}
.toast{padding:10px 14px;border-radius:8px;margin:14px 0;font-weight:600}
.toast.ok{background:rgba(0,255,204,.1);color:var(--ac);border:1px solid var(--ac)}
.toast.err{background:rgba(255,68,68,.1);color:var(--red);border:1px solid var(--red)}
.drop{background:var(--card);border:1px dashed #444;padding:18px;border-radius:8px;text-align:center;color:var(--mut);margin-bottom:12px}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.center{display:flex;justify-content:center;align-items:center;min-height:90vh}
.badge{background:rgba(0,255,204,.1);color:var(--ac);padding:5px 15px;border-radius:20px;border:1px solid var(--ac);font-size:14px}
`;

const page = (title, body, script = '') => `<!DOCTYPE html>
<html lang="th"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title><style>${CSS}</style></head>
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
    res.send(page('VOID HUB API', `
        <div class="center" style="text-align:center"><div>
            <h1 style="font-size:40px">VOID HUB API</h1>
            <p class="sub">ระบบโฮสต์สคริปต์ออนไลน์ (Raw Script Server)</p>
            <div style="margin-top:40px"><span class="badge">● ระบบออนไลน์</span></div>
        </div></div>`));
});

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
            return res.status(404).type('text/plain').send('Script not found');
        }
        const s = await Script.findOne({ filename: req.params.filename }, 'content').lean();
        if (!s) return res.status(404).type('text/plain').send('Script not found');
        res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' });
        res.send(s.content);
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
        <div class="center"><div class="card" style="width:100%;max-width:340px;text-align:center">
            <h2 style="margin-bottom:24px">🔐 Admin Login</h2>
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
                <div><h2>🛠️ Void Hub Dashboard</h2><div class="sub">ไฟล์ทั้งหมด ${scripts.length} รายการ</div></div>
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
        res.redirect(`${DASH}?m=uploaded`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving to database');
    }
});

app.post('/delete', requireAuth, checkCsrf, async (req, res) => {
    try {
        await Script.deleteOne({ filename: str(req.body.filename) });
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
