const express = require('express');
const session = require('express-session');
const multer = require('multer');
const mongoose = require('mongoose');
require('dotenv').config();
const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.use(session({
    secret: 'VoidHubSecretKey_ChangeThis',
    resave: false,
    saveUninitialized: true
}));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MyPassword123';

// 🔗 เชื่อมต่อ MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// 📦 สร้าง Schema สำหรับเก็บข้อมูลสคริปต์
const ScriptSchema = new mongoose.Schema({
    filename: { type: String, required: true, unique: true },
    content: { type: String, required: true }
});
const Script = mongoose.model('Script', ScriptSchema);

// 🟢 หน้าแรกสุด
app.get('/', (req, res) => {
    res.send(`<body style="background:#111;color:#fff;font-family:sans-serif;text-align:center;padding-top:100px;">
            <h1 style="color:#00ffcc;">VOID HUB API</h1>
            <p>ระบบโฮสต์สคริปต์ออนไลน์ (Raw Script Server)</p>
            <br><br><a href="/admin" style="color:#00ffcc;text-decoration:none;border:1px solid #00ffcc;padding:10px 20px;border-radius:5px;">🔐 เข้าสู่ระบบแอดมิน</a>
        </body>`);
});

// 🟢 1. ส่วนสำหรับคนทั่วไป (PUBLIC) - ดึงข้อมูลจาก MongoDB
app.get('/raw/:filename', async (req, res) => {
    try {
        const script = await Script.findOne({ filename: req.params.filename });
        if (script) {
            res.setHeader('Content-Type', 'text/plain');
            res.send(script.content);
        } else {
            res.status(404).send('Script not found');
        }
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// 🔐 2. ส่วนสำหรับแอดมิน (ADMIN)
app.get('/admin', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/dashboard');
    res.send(`<body style="background:#111;color:#fff;font-family:sans-serif;text-align:center;padding-top:100px;">
            <h2>Void Hub Admin</h2>
            <form action="/login" method="POST">
                <input type="password" name="password" placeholder="ใส่รหัสผ่าน" style="padding:10px;border-radius:5px;border:none;">
                <button type="submit" style="padding:10px 20px;background:#00ffcc;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">เข้าสู่ระบบ</button>
            </form>
        </body>`);
});

app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/dashboard');
    } else {
        res.send('รหัสผ่านผิด! <a href="/admin">ลองใหม่</a>');
    }
});

app.get('/dashboard', async (req, res) => {
    if (!req.session.loggedIn) return res.redirect('/admin');
    try {
        const allScripts = await Script.find({});
        let fileList = allScripts.map(s => `<li>${s.filename} <a href="/raw/${s.filename}" target="_blank">[ดู Raw]</a></li>`).join('');
        res.send(`<body style="background:#111;color:#fff;font-family:sans-serif;padding:20px;">
                <h2>🛠️ Void Hub Dashboard</h2>
                <h3>📜 รายการไฟล์:</h3>
                <ul>${fileList || 'ยังไม่มีไฟล์'}</ul>
                <hr style="border-color:#333; margin: 20px 0;">
                <h3>📁 อัปโหลดไฟล์ (.lua / .txt):</h3>
                <form action="/upload" method="POST" enctype="multipart/form-data" style="margin-bottom: 30px; background:#222; padding:15px; border-radius:8px;">
                    <input type="file" name="luaFile" accept=".lua,.txt" required style="color:#fff; margin-bottom:10px;"><br>
                    <button type="submit" style="padding:10px 20px;background:#5865F2;color:#fff;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">⬆️ อัปโหลดไฟล์</button>
                </form>
                <h3>✍️ หรือ พิมพ์โค้ดเอง:</h3>
                <form action="/save" method="POST">
                    <input type="text" name="filename" placeholder="ชื่อไฟล์ (เช่น main.lua)" required style="padding:10px;width:100%;margin-bottom:10px;background:#222;color:#fff;border:1px solid #444;"><br>
                    <textarea name="content" rows="5" placeholder="วางโค้ด Lua ที่นี่..." required style="padding:10px;width:100%;margin-bottom:10px;background:#222;color:#fff;border:1px solid #444;font-family:monospace;"></textarea><br>
                    <button type="submit" style="padding:10px 20px;background:#00ffcc;border:none;border-radius:5px;font-weight:bold;cursor:pointer;">💾 บันทึกโค้ด</button>
                </form>
                <br><br><a href="/logout" style="color:#ff5555;">ออกจากระบบ (Logout)</a>
            </body>`);
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// 📁 อัปโหลดไฟล์ -> บันทึกลง MongoDB
app.post('/upload', upload.single('luaFile'), async (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    if (!req.file) return res.status(400).send('ไม่มีไฟล์อัปโหลด');
    try {
        await Script.findOneAndUpdate(
            { filename: req.file.originalname },
            { content: req.file.buffer.toString('utf-8') },
            { upsert: true, new: true }
        );
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Error saving to database');
    }
});

// ✍️ พิมพ์โค้ดเอง -> บันทึกลง MongoDB
app.post('/save', async (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    try {
        await Script.findOneAndUpdate(
            { filename: req.body.filename },
            { content: req.body.content },
            { upsert: true, new: true }
        );
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Error saving to database');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));