const express = require('express');
const session = require('express-session');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'VoidHubSecretKey_ChangeThis',
    resave: false,
    saveUninitialized: true
}));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MyPassword123';

let scripts = {
    "example.lua": "-- นี่คือตัวอย่างสคริปต์\nprint('Hello Void Hub!')"
};

// 🟢 หน้าแรกสุด (หน้าเว็บหลัก)
app.get('/', (req, res) => {
    res.send(`
        <body style="background:#111;color:#fff;font-family:sans-serif;text-align:center;padding-top:100px;">
            <h1 style="color:#00ffcc;font-size:40px;">VOID HUB API</h1>
            <p>ระบบโฮสต์สคริปต์ออนไลน์ (Raw Script Server)</p>
            <br><br>
            <a href="/admin" style="color:#00ffcc;text-decoration:none;border:1px solid #00ffcc;padding:10px 20px;border-radius:5px;font-weight:bold;">
                🔐 เข้าสู่ระบบแอดมิน
            </a>
        </body>
    `);
});

// 🟢 1. ส่วนสำหรับคนทั่วไป (PUBLIC) - ดู Raw ได้อย่างเดียว
app.get('/raw/:filename', (req, res) => {
    const filename = req.params.filename;
    const scriptContent = scripts[filename];

    if (scriptContent) {
        res.setHeader('Content-Type', 'text/plain');
        res.send(scriptContent);
    } else {
        res.status(404).send('Script not found');
    }
});

// 🔐 2. ส่วนสำหรับแอดมิน (ADMIN)
app.get('/admin', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/dashboard');
    res.send(`
        <body style="background:#111;color:#fff;font-family:sans-serif;text-align:center;padding-top:100px;">
            <h2>Void Hub Admin</h2>
            <form action="/login" method="POST">
                <input type="password" name="password" placeholder="ใส่รหัสผ่าน" style="padding:10px;border-radius:5px;border:none;">
                <button type="submit" style="padding:10px 20px;background:#00ffcc;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">เข้าสู่ระบบ</button>
            </form>
        </body>
    `);
});

app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/dashboard');
    } else {
        res.send('รหัสผ่านผิด! <a href="/admin">ลองใหม่</a>');
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.loggedIn) return res.redirect('/admin');

    let fileList = Object.keys(scripts).map(f => `<li>${f} <a href="/raw/${f}" target="_blank">[ดู Raw]</a></li>`).join('');

    res.send(`
        <body style="background:#111;color:#fff;font-family:sans-serif;padding:20px;">
            <h2>🛠️ Void Hub Dashboard</h2>
            <p>ล็อกอินสำเร็จ! คุณสามารถแก้ไขสคริปต์ได้</p>
            
            <h3>📜 รายการไฟล์:</h3>
            <ul>${fileList || 'ยังไม่มีไฟล์'}</ul>

            <hr style="border-color:#333; margin: 20px 0;">
            
            <h3>✍️ สร้าง/แก้ไข ไฟล์ Raw:</h3>
            <form action="/save" method="POST">
                <input type="text" name="filename" placeholder="ชื่อไฟล์ (เช่น main.lua)" required style="padding:10px;width:100%;margin-bottom:10px;background:#222;color:#fff;border:1px solid #444;"><br>
                <textarea name="content" rows="10" placeholder="วางโค้ด Lua ที่นี่..." required style="padding:10px;width:100%;margin-bottom:10px;background:#222;color:#fff;border:1px solid #444;font-family:monospace;"></textarea><br>
                <button type="submit" style="padding:10px 20px;background:#00ffcc;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">บันทึกโค้ด</button>
            </form>
            <br>
            <a href="/logout" style="color:#ff5555;">ออกจากระบบ (Logout)</a>
        </body>
    `);
});

app.post('/save', (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    
    const { filename, content } = req.body;
    scripts[filename] = content;
    res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// เริ่มรันเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});