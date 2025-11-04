// app.js
// Tek dosyalık Node.js uygulaması: frontend + backend + OCR + MongoDB
// Usage:
// 1) npm init -y
// 2) npm install express multer mongoose tesseract.js jsonwebtoken dotenv cors
// 3) create .env (see below)
// 4) node app.js
//
// .env example:
// MONGO_URI=mongodb://127.0.0.1:27017/mebi_clone
// PORT=4000
// ADMIN_PASS=SeninGizliParolan123
// JWT_SECRET=çok_gizli_değiştirin
// JWT_EXPIRES=4h

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const Tesseract = require('tesseract.js');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/mebi_clone';
const ADMIN_PASS = process.env.ADMIN_PASS || 'change_me';
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_secret';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '2h';

// Multer setup (temp uploads)
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB limit per file

// Mongoose setup
mongoose.set('strictQuery', false);
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

const questionSchema = new mongoose.Schema({
  text: { type: String, required: true },
  sourceImageName: { type: String },
  createdAt: { type: Date, default: () => new Date() },
});
const Question = mongoose.model('Question', questionSchema);

// Simple auth: POST /api/auth { password } => { token }
app.post('/api/auth', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });
  if (password !== ADMIN_PASS) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.json({ ok: true, token });
});

function ensureAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ ok: false, error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ ok: false, error: 'Bad Authorization format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}

// OCR helper: try Turkish first, fallback to English if fails
async function runOCR(imagePath) {
  // Use logger quiet to avoid too noisy console
  try {
    const res = await Tesseract.recognize(imagePath, 'tur', { logger: m => {} });
    if (res && res.data && res.data.text && res.data.text.trim().length > 5) {
      return res.data.text;
    }
    // fallback to 'eng'
    const res2 = await Tesseract.recognize(imagePath, 'eng', { logger: m => {} });
    return (res2 && res2.data && res2.data.text) ? res2.data.text : '';
  } catch (err) {
    // final fallback try english
    try {
      const res3 = await Tesseract.recognize(imagePath, 'eng', { logger: m => {} });
      return (res3 && res3.data && res3.data.text) ? res3.data.text : '';
    } catch (err2) {
      console.error('OCR failed:', err2.message || err2);
      return '';
    }
  }
}

// Basic conservative question extraction tuned for exam pages (numerical prefixes, question marks, keywords)
function extractQuestionsFromText(raw) {
  if (!raw) return [];
  // Normalize line endings and trim
  let text = raw.replace(/\r/g, '\n').replace(/\t/g, ' ').replace(/\u00A0/g, ' ').trim();
  // Merge multiple spaces
  text = text.replace(/ {2,}/g, ' ');
  // First try to split by numbered patterns (e.g., "1.", "1)", "Soru 1:", newline + number)
  let parts = text.split(/(?=\n\s*\d+\s*[\.\):-])/g).map(p => p.trim()).filter(Boolean);

  // If we didn't get anything useful, try splitting on lines and grouping lines that contain '?' or math keywords
  if (parts.length === 0) {
    const lines = text.split(/\n+/).map(l => l.trim()).filter(Boolean);
    const candidates = [];
    let buffer = '';
    for (const line of lines) {
      // If line looks like the start of a numbered question
      if (/^\d+\s*[\.\):-]/.test(line)) {
        if (buffer) { candidates.push(buffer.trim()); buffer = ''; }
        buffer += ' ' + line;
      } else if (/\?|kaç|bulun|bulunuz|değer|eşittir|hesapla|sonuç|sonuçları|gösteriniz|aşağıdakiler/i.test(line)) {
        // treat as question-containing line
        if (buffer) { buffer += ' ' + line; candidates.push(buffer.trim()); buffer = ''; }
        else candidates.push(line);
      } else {
        // accumulate ambiguous lines (e.g., multiline question)
        if (buffer) buffer += ' ' + line;
        else buffer = line;
      }
    }
    if (buffer) candidates.push(buffer.trim());
    parts = candidates.filter(p => p.length > 10);
  }

  // post-process each part: remove excessive newlines, trim
  const results = parts.map(p => {
    const cleaned = p.replace(/\n+/g, ' ').replace(/\s{2,}/g, ' ').trim();
    return { text: cleaned };
  }).filter(r => r.text.length > 10);

  return results;
}

// Upload endpoint (only admin via JWT)
app.post('/api/upload', ensureAuth, upload.array('images', 30), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ ok: false, error: 'No files uploaded' });

    const inserted = [];
    for (const file of req.files) {
      const imgPath = path.resolve(file.path);
      // OCR
      const text = await runOCR(imgPath);
      const qs = extractQuestionsFromText(text);

      // Save parsed questions to MongoDB as text entries
      if (qs.length > 0) {
        const docs = qs.map(q => ({ text: q.text, sourceImageName: file.originalname }));
        const insertedDocs = await Question.insertMany(docs);
        // convert insertedDocs to plain objects for response
        inserted.push(...Object.values(insertedDocs).map(d => ({ text: d.text, sourceImageName: d.sourceImageName })));
      } else {
        // If no detected question, still store whole raw text as one entry to avoid loss
        if (text && text.trim().length > 10) {
          const doc = await Question.create({ text: text.trim(), sourceImageName: file.originalname });
          inserted.push({ text: doc.text, sourceImageName: doc.sourceImageName });
        }
      }

      // remove temp file
      try { fs.unlinkSync(imgPath); } catch (e) { /* ignore */ }
    }

    return res.json({ ok: true, insertedCount: inserted.length, examples: inserted.slice(0, 30) });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ ok: false, error: err.message || 'Server error' });
  }
});

// Public: get math questions (students will use this)
app.get('/api/questions', async (req, res) => {
  try {
    const rows = await Question.find({}).sort({ createdAt: -1 }).limit(1000).lean();
    res.json({ ok: true, questions: rows });
  } catch (err) {
    console.error('Fetch questions error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Serve simple frontend (single page) — red theme, admin login + upload
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Matematik - Soru Yükleyici</title>
<style>
:root{ --red:#C30000; --muted:#f6f6f6; --card:#ffffff; --dark:#222; }
body{ margin:0; font-family:Inter,Segoe UI,Roboto,Arial,sans-serif; background:var(--muted); color:var(--dark); }
.container{ max-width:1100px; margin:28px auto; padding:18px; }
.header{ display:flex; align-items:center; justify-content:space-between; gap:12px; }
.brand{ display:flex; align-items:center; gap:12px; }
.logo{ width:48px; height:48px; border-radius:10px; background:var(--red); box-shadow: 0 6px 20px rgba(195,0,0,0.18); }
.title{ font-weight:700; color:var(--red); font-size:20px; }
.card{ background:var(--card); padding:16px; border-radius:12px; box-shadow: 0 6px 18px rgba(0,0,0,0.06); margin-top:16px; }
.button{ background:var(--red); color:#fff; border:none; padding:10px 14px; border-radius:10px; cursor:pointer; font-weight:600; }
.input{ padding:10px 12px; border-radius:8px; border:1px solid #e6e6e6; }
.small{ font-size:13px; color:#666; }
.files-row{ display:flex; gap:8px; margin-top:10px; align-items:center; }
.preview img{ max-height:120px; border-radius:8px; border:1px solid #eee; object-fit:contain; }
.questions-list{ margin-top:12px; }
.q{ padding:12px; border-bottom:1px solid #f2f2f2; }
.q .meta{ font-size:12px; color:#777; margin-top:8px; }
.center{ text-align:center; }
.footer{ margin-top:18px; font-size:13px; color:#555; }
@media(max-width:720px){ .header{ flex-direction:column; align-items:flex-start; gap:8px; } .files-row{ flex-direction:column; align-items:flex-start; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <div class="title">Matematik • Soru Yükleyici</div>
        <div class="small">Kırmızı tema — Otomatik OCR ile soruları metne çevirir</div>
      </div>
    </div>
    <div id="auth-area">
      <form id="login-form" onsubmit="return false;" style="display:flex;gap:8px;align-items:center;">
        <input id="admin-pass" class="input" type="password" placeholder="Admin parola" />
        <button id="login-btn" class="button">Giriş</button>
      </form>
      <div id="admin-actions" style="display:none; gap:8px; align-items:center;">
        <span class="small">Admin girişli</span>
        <button id="logout-btn" class="button" style="background:#555">Çıkış</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h3>Yükleme (sadece admin)</h3>
    <p class="small">Fotoğrafları seçip OCR ile otomatik olarak Matematik bölümüne ekleyin.</p>

    <div id="upload-area">
      <div style="margin-top:8px" class="files-row">
        <input id="file-input" type="file" accept="image/*" multiple />
        <button id="upload-btn" class="button">Yükle ve OCR'la</button>
      </div>
      <div id="previews" class="preview" style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;"></div>

      <div id="upload-result" style="margin-top:12px"></div>
    </div>

  </div>

  <div class="card">
    <h3>Matematik Soruları (Öğrenciler Görebilir)</h3>
    <div id="questions" class="questions-list">
      <div class="center small">Yükleniyor...</div>
    </div>
  </div>

  <div class="footer small">Not: OCR doğruluğu için iyi aydınlatma ve net çekim önerilir.</div>
</div>

<script>
const API = '/api';
let token = localStorage.getItem('admin_token') || '';

function el(id){ return document.getElementById(id); }

async function fetchQuestions(){
  try{
    const r = await fetch(API + '/questions');
    const j = await r.json();
    if (j.ok){
      renderQuestions(j.questions);
    } else {
      el('questions').innerHTML = '<div class="center small">Soru alınamadı.</div>';
    }
  }catch(e){
    el('questions').innerHTML = '<div class="center small">Sunucuya bağlanamadı.</div>';
  }
}

function renderQuestions(list){
  if(!list || list.length === 0){
    el('questions').innerHTML = '<div class="center small">Henüz soru yok.</div>'; return;
  }
  el('questions').innerHTML = '';
  list.forEach(q => {
    const d = document.createElement('div'); d.className = 'q';
    const p = document.createElement('div'); p.style.whiteSpace='pre-wrap'; p.textContent = q.text;
    const m = document.createElement('div'); m.className='meta'; m.textContent = 'Kaynak: ' + (q.sourceImageName || '—') + ' • ' + new Date(q.createdAt).toLocaleString();
    d.appendChild(p); d.appendChild(m);
    el('questions').appendChild(d);
  });
}

async function loginFlow(){
  const pass = el('admin-pass').value.trim();
  if(!pass) return alert('Parolayı girin');
  try{
    const r = await fetch(API + '/auth', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pass }) });
    const j = await r.json();
    if(j.ok && j.token){
      token = j.token;
      localStorage.setItem('admin_token', token);
      toggleAuth(true);
      alert('Giriş başarılı');
    } else {
      alert('Giriş başarısız');
    }
  }catch(e){ alert('Giriş hatası'); console.error(e); }
}

function toggleAuth(isAuth){
  if(isAuth){
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('admin-actions').style.display = 'flex';
  } else {
    document.getElementById('login-form').style.display = 'flex';
    document.getElementById('admin-actions').style.display = 'none';
    localStorage.removeItem('admin_token');
    token = '';
  }
}

document.getElementById('login-btn').addEventListener('click', loginFlow);
document.getElementById('logout-btn').addEventListener('click', () => { toggleAuth(false); });

const fileInput = el('file-input');
const previews = el('previews');
fileInput.addEventListener('change', () => {
  previews.innerHTML = '';
  Array.from(fileInput.files).forEach(f => {
    const img = document.createElement('img');
    img.src = URL.createObjectURL(f);
    img.onload = () => URL.revokeObjectURL(img.src);
    img.style.maxWidth = '140px';
    previews.appendChild(img);
  });
});

document.getElementById('upload-btn').addEventListener('click', async () => {
  if(!token) return alert('Önce admin girişi yapın');
  if(!fileInput.files || fileInput.files.length === 0) return alert('En az bir görsel seçin');
  const fd = new FormData();
  Array.from(fileInput.files).forEach(f => fd.append('images', f));
  const btn = el('upload-btn'); btn.disabled = true; btn.textContent = 'Yükleniyor...';
  try{
    const r = await fetch(API + '/upload', { method:'POST', headers: { 'Authorization': 'Bearer ' + token }, body: fd });
    const j = await r.json();
    if(j.ok){
      el('upload-result').innerHTML = '<div style="color:green">Başarılı — ' + j.insertedCount + ' soru eklendi.</div>';
      fileInput.value = ''; previews.innerHTML = '';
      fetchQuestions();
    } else {
      el('upload-result').innerHTML = '<div style="color:#a00">Hata: ' + (j.error || 'Bilinmeyen hata') + '</div>';
    }
  }catch(e){
    el('upload-result').innerHTML = '<div style="color:#a00">Sunucu hatası. Konsolu kontrol et.</div>';
    console.error(e);
  } finally {
    btn.disabled = false; btn.textContent = 'Yükle ve OCR\'la';
  }
});

// init
if(token) toggleAuth(true);
fetchQuestions();
</script>
</body>
</html>`);
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 App listening on http://localhost:' + PORT);
  console.log('• Admin login endpoint: POST /api/auth { password }');
  console.log('• Upload endpoint (admin): POST /api/upload (form-data key: images)');
  console.log('• Questions (public): GET /api/questions');
});
