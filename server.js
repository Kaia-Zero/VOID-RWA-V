const express = require('express');
const session = require('express-session');
const app = express();

// ตั้งค่าให้รับข้อมูลแบบ JSON และ Form
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ตั้งค่า Session (ใช้จำว่าคุณล็อกอินแล้ว)
app.use(session({
    secret: 'ZeroHubSecretKey_ChangeThis', // เปลี่ยนเป็นอะไรก็ได้ที่คาดเดายาก
    resave: false,
    saveUninitialized: true
}));

// ⚠️ รหัสผ่านของคุณ (แก้ตรงนี้)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MyPassword123';

// ฐานข้อมูลชั่วคราว (เก็บโค้ด Lua ไว้ในตัวแปร)
// *หมายเหตุ: ถ้า Render รีสตาร์ท ข้อมูลจะหาย ให้ใช้วิธีเซฟลงไฟล์หรือ Database ภายหลัง
let scripts = {
    "example.lua": "-- นี่คือตัวอย่างสคริปต์\nprint('Hello Zero Hub!')"
};

// ----------------------------------------------------
// 🟢 1. ส่วนสำหรับคนทั่วไป (PUBLIC) - ดู Raw ได้อย่างเดียว
// ----------------------------------------------------
app.get('/raw/:filename', (req, res) => {
    const filename = req.params.filename;
    const scriptContent = scripts[filename];

    if (scriptContent) {
        // ส่งข้อมูลกลับเป็น text ธรรมดา (Raw) ไม่ใช่ HTML
        res.setHeader('Content-Type', 'text/plain');
        res.send(scriptContent);
    } else {
        res.status(404).send('Script not found');
    }
});

// ----------------------------------------------------
// 🔐 2. ส่วนสำหรับแอดมิน (ADMIN) - ต้องล็อกอินก่อน
// ----------------------------------------------------

// หน้า Login
app.get('/admin', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/dashboard');
    res.send(`
        <body style="background:#111;color:#fff;font-family:sans-serif;text-align:center;padding-top:100px;">
            <h2>Zero Hub Admin</h2>
            <form action="/login" method="POST">
                <input type="password" name="password" placeholder="ใส่รหัสผ่าน" style="padding:10px;border-radius:5px;border:none;">
                <button type="submit" style="padding:10px 20px;background:#00ffcc;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">เข้าสู่ระบบ</button>
            </form>
        </body>
    `);
});

// ตรวจสอบรหัสผ่าน
app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/dashboard');
    } else {
        res.send('รหัสผ่านผิด! <a href="/admin">ลองใหม่</a>');
    }
});

// หน้า Dashboard (ต้องล็อกอินก่อนถึงจะเห็น)
app.get('/dashboard', (req, res) => {
    if (!req.session.loggedIn) return res.redirect('/admin');

    // สร้างรายการไฟล์ทั้งหมด
    let fileList = Object.keys(scripts).map(f => `<li>${f} <a href="/raw/${f}" target="_blank">[ดู Raw]</a></li>`).join('');

    res.send(`
        <body style="background:#111;color:#fff;font-family:sans-serif;padding:20px;">
            <h2>🛠️ Zero Hub Dashboard</h2>
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

// บันทึกโค้ด (ต้องล็อกอินก่อน)
app.post('/save', (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    
    const { filename, content } = req.body;
    scripts[filename] = content;
    res.redirect('/dashboard');
});

// ออกจากระบบ
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// เริ่มรันเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});