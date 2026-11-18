const express = require('express');
const session = require('express-session');
const multer = require('multer');
const mongoose = require('mongoose');
require('dotenv').config();
const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'default_fallback_secret_do_not_use', 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MyPassword123';

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

const ScriptSchema = new mongoose.Schema({
    filename: { type: String, required: true, unique: true },
    content: { type: String, required: true }
});
const Script = mongoose.model('Script', ScriptSchema);

// หน้าแรกสุด (หน้าบ้าน)
app.get('/', (req, res) => {
    res.send(`
        <body style="background:#0a0a0a;color:#fff;font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;text-align:center;padding-top:100px;">
            <h1 style="color:#00ffcc;font-size:40px;text-shadow: 0 0 10px rgba(0,255,204,0.5);">VOID HUB API</h1>
            <p style="color:#888;">ระบบโฮสต์สคริปต์ออนไลน์ (Raw Script Server)</p>
            <div style="margin-top:50px;">
                <span style="background:rgba(0,255,204,0.1); color:#00ffcc; padding:5px 15px; border-radius:20px; border:1px solid #00ffcc; font-size:14px;">● ระบบออนไลน์</span>
            </div>
        </body>
    `);
});

// ส่วนดึง Raw Script
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

// หน้า Login แอดมิน
const SECRET_ADMIN_PATH = process.env.SECRET_ADMIN_PATH || 'void-admin-9988'; 

app.get(`/${SECRET_ADMIN_PATH}`, (req, res) => {
    if (req.session.loggedIn) return res.redirect(`/${SECRET_ADMIN_PATH}/dashboard`);
    res.send(`
        <body style="background:#0a0a0a;color:#fff;font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
            <div style="background:#15151a;padding:40px;border-radius:15px;border:1px solid #333;text-align:center;width:300px;box-shadow: 0 0 20px rgba(0,255,204,0.1);">
                <h2 style="color:#00ffcc;margin-bottom:30px;">🔐 Admin Login</h2>
                <form action="/login" method="POST">
                    <input type="password" name="password" placeholder="รหัสผ่าน" style="width:100%;padding:12px;margin-bottom:15px;background:#0a0a0a;border:1px solid #444;border-radius:8px;color:#fff;box-sizing:border-box;outline:none;">
                    <button type="submit" style="width:100%;padding:12px;background:#00ffcc;border:none;border-radius:8px;font-weight:bold;cursor:pointer;color:#000;font-size:16px;">เข้าสู่ระบบ</button>
                </form>
            </div>
        </body>
    `);
});

app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.loggedIn = true;
        res.redirect(`/${SECRET_ADMIN_PATH}/dashboard`);
    } else {
        setTimeout(() => {
            res.send('<body style="background:#0a0a0a;color:red;text-align:center;padding-top:100px;">รหัสผ่านผิด! <a href="/" style="color:#00ffcc;">กลับหน้าแรก</a></body>');
        }, 2000);
    }
});

// 🛠️ หน้า Dashboard (ปรับโฉมใหม่ทั้งหมด)
app.get(`/${SECRET_ADMIN_PATH}/dashboard`, async (req, res) => {
    if (!req.session.loggedIn) return res.redirect(`/${SECRET_ADMIN_PATH}`);
    try {
        const allScripts = await Script.find({});
        
        // สร้างรายการไฟล์
        let fileList = allScripts.map(s => `
            <li style="background:#0a0a0a;padding:15px;margin-bottom:10px;border-radius:8px;border:1px solid #333;display:flex;justify-content:space-between;align-items:center;">
                <span style="font-family:monospace;color:#00ffcc;">📄 ${s.filename}</span>
                <a href="/raw/${s.filename}" target="_blank" style="background:#5865F2;color:#fff;text-decoration:none;padding:5px 15px;border-radius:5px;font-size:14px;font-weight:bold;">ดู Raw</a>
            </li>
        `).join('');

        res.send(`
            <!DOCTYPE html>
            <html lang="th">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Void Hub - Dashboard</title>
                <style>
                    body {
                        background-color: #0a0a0a;
                        color: #fff;
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        margin: 0;
                        padding: 20px;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    h2 { color: #00ffcc; text-shadow: 0 0 10px rgba(0,255,204,0.3); }
                    h3 { color: #ccc; border-bottom: 1px solid #333; padding-bottom: 10px; margin-top: 30px; }
                    ul { list-style: none; padding: 0; }
                    input[type="text"], textarea {
                        width: 100%;
                        padding: 12px;
                        background: #15151a;
                        border: 1px solid #444;
                        border-radius: 8px;
                        color: #fff;
                        margin-bottom: 15px;
                        box-sizing: border-box;
                        font-family: monospace;
                        outline: none;
                    }
                    input[type="text"]:focus, textarea:focus { border-color: #00ffcc; }
                    .btn-group { display: flex; gap: 10px; margin-top: 10px; }
                    .btn {
                        padding: 12px 20px;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: bold;
                        font-size: 15px;
                        transition: 0.2s;
                    }
                    .btn-upload { background: #5865F2; color: #fff; width: 100%; }
                    .btn-upload:hover { background: #4752C4; }
                    .btn-save { background: #00ffcc; color: #000; flex: 1; }
                    .btn-save:hover { background: #00ccaa; }
                    .btn-logout { 
                        display: block; 
                        text-align: center; 
                        background: transparent; 
                        color: #ff5555; 
                        border: 1px solid #ff5555; 
                        text-decoration: none; 
                        padding: 10px; 
                        border-radius: 8px; 
                        margin-top: 40px;
                        font-weight: bold;
                    }
                    .btn-logout:hover { background: rgba(255,85,85,0.1); }
                    .file-input-wrapper {
                        background: #15151a;
                        border: 1px dashed #444;
                        padding: 20px;
                        border-radius: 8px;
                        text-align: center;
                        margin-bottom: 15px;
                    }
                    input[type="file"] { color: #888; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>🛠️ Void Hub Dashboard</h2>
                    <p style="color:#888; font-size:14px;">จัดการระบบสคริปต์ของคุณ</p>

                    <h3>📜 รายการไฟล์ในระบบ</h3>
                    <ul>${fileList || '<li style="color:#888;">ยังไม่มีไฟล์ในระบบ</li>'}</ul>

                    <h3>📁 อัปโหลดไฟล์ (.lua / .txt)</h3>
                    <form action="/upload" method="POST" enctype="multipart/form-data">
                        <div class="file-input-wrapper">
                            <input type="file" name="luaFile" accept=".lua,.txt" required>
                        </div>
                        <button type="submit" class="btn btn-upload">⬆️ อัปโหลดไฟล์ขึ้นระบบ</button>
                    </form>

                    <h3>✍️ สร้าง/แก้ไข โค้ด</h3>
                    <form action="/save" method="POST">
                        <input type="text" name="filename" placeholder="ชื่อไฟล์ (เช่น main.lua)" required>
                        <textarea name="content" rows="8" placeholder="วางโค้ด Lua ที่นี่..." required></textarea>
                        <button type="submit" class="btn btn-save">💾 บันทึกโค้ด</button>
                    </form>

                    <a href="/logout" class="btn-logout">ออกจากระบบ (Logout)</a>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// ส่วนอัปโหลดไฟล์
app.post('/upload', upload.single('luaFile'), async (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    if (!req.file) return res.status(400).send('ไม่มีไฟล์อัปโหลด');
    try {
        await Script.findOneAndUpdate(
            { filename: req.file.originalname },
            { content: req.file.buffer.toString('utf-8') },
            { upsert: true, new: true }
        );
        res.redirect(`/${SECRET_ADMIN_PATH}/dashboard`);
    } catch (err) {
        res.status(500).send('Error saving to database');
    }
});

// ส่วนบันทึกโค้ด
app.post('/save', async (req, res) => {
    if (!req.session.loggedIn) return res.status(403).send('Access Denied');
    try {
        await Script.findOneAndUpdate(
            { filename: req.body.filename },
            { content: req.body.content },
            { upsert: true, new: true }
        );
        res.redirect(`/${SECRET_ADMIN_PATH}/dashboard`);
    } catch (err) {
        res.status(500).send('Error saving to database');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));