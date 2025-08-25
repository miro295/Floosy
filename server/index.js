// server/index.js
import 'dotenv/config';

import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import { body, validationResult, matchedData } from "express-validator";
import crypto from "crypto";
import nodemailer from "nodemailer";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;

// مدة صلاحية PIN بالثواني (2 دقيقة)
const TOPUP_PIN_TTL_SEC = 120;

// ----- OTP/PIN Security (new) -----
const OTP_CODE_TTL_SEC = 120;                 // OTP validity: 2 minutes
const OTP_SEND_DAILY_MAX = 10;                // max OTP sends per email/day
const OTP_VERIFY_DAILY_WRONG_MAX = 100;       // max wrong OTP verifies per email+IP/day
const OTP_SEND_COOLDOWN_SEC_DEFAULT = 60;     // resend cooldown (most flows)
const OTP_SEND_COOLDOWN_SEC_FORGOT_PW = 120;  // resend cooldown for forgot-password

// ====== Security & Config ======
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SUPER_SECRET_KEY";
if (JWT_SECRET === "CHANGE_ME_SUPER_SECRET_KEY") {
  console.warn("⚠️ استخدم متغيّر بيئة JWT_SECRET في الإنتاج!");
}

const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.GMAIL_USER || "no-reply@floosy.com";

// جهاز الأدمن
const ADMIN_BIND_KEY = process.env.ADMIN_BIND_KEY || "";
const ADMIN_DEVICE_SECRET = process.env.ADMIN_DEVICE_SECRET || "";
const ADMIN_DEVICE_ENFORCE = String(process.env.ADMIN_DEVICE_ENFORCE || "0") === "1";

// IP allowlist (اختياري)
const ADMIN_IP_WHITELIST = (process.env.ADMIN_IP_WHITELIST || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// Origins
const ALLOWED_ORIGINS = new Set([
  "https://floosy.com",
  "http://localhost:3000",
  "http://localhost:5000",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5000",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
]);

// ====== Mailer ======
const MAIL_FROM = process.env.GMAIL_USER || "no-reply@floosy.com";
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
});

// ====== Express base ======
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(
  helmet({
    hidePoweredBy: true,
    referrerPolicy: { policy: "no-referrer" },
    frameguard: { action: "sameorigin" },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https://flagcdn.com"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'self'"],
      },
    },
  })
);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);
      return cb(new Error("CORS: Origin not allowed"), false);
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "200kb" }));
app.use(morgan("dev"));

// ====== Rate limits ======
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// محاولات دخول المستخدم / الأدمن
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many attempts, try again shortly" },
});
// تشديد لطلبات OTP: 3 طلبات/دقيقة لكل IP
const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "محاولات كثيرة. جرّب بعد دقيقة." },
});

// ====== Helpers (cookie, csrf, device) ======
function getCookie(req, name) {
  const cookie = String(req.headers.cookie || "");
  const m = cookie.match(new RegExp("(?:^|\\s*;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : "";
}

const isProd = process.env.NODE_ENV === "production";
function setCookie(res, name, value, opts = {}) {
  res.cookie?.(name, value, {
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
    path: "/",
    ...opts,
  });
}
function setReadableCookie(res, name, value, opts = {}) {
  res.cookie?.(name, value, {
    httpOnly: false,
    sameSite: "strict",
    secure: isProd,
    path: "/",
    ...opts,
  });
}

function signDevice(ua = "") {
  if (!ADMIN_DEVICE_SECRET) return "";
  return crypto.createHmac("sha256", ADMIN_DEVICE_SECRET).update(String(ua)).digest("hex");
}

function ipAllowed(req) {
  if (!ADMIN_IP_WHITELIST.length) return true;
  const ip = (req.ip || req.connection?.remoteAddress || "").toString();
  return ADMIN_IP_WHITELIST.includes(ip);
}

// ====== DB ======
const db = new sqlite3.Database(path.join(__dirname, "data", "floosy.db"), (err) => {
  if (err) console.error("❌ DB error:", err.message);
  else console.log("✅ SQLite connected");
});

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON;`);

  // Users
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password TEXT,
      password_hash TEXT,
      balance REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      allow_services INTEGER NOT NULL DEFAULT 0,
      account_number TEXT UNIQUE
    );
  `);

  // لأجل قواعد قديمة بدون العمود:
  db.run(`ALTER TABLE users ADD COLUMN allow_services INTEGER NOT NULL DEFAULT 0`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN account_number TEXT UNIQUE`, () => {});

  db.run(`
    CREATE TRIGGER IF NOT EXISTS prevent_negative_balance
    BEFORE UPDATE ON users
    FOR EACH ROW
    WHEN NEW.balance < 0
    BEGIN
      SELECT RAISE(ABORT, 'Balance cannot be negative');
    END;
  `);

  // Transactions
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,       -- topup | withdraw | transfer_in | transfer_out | admin_adj
      amount REAL NOT NULL,     -- always positive
      balance_after REAL NOT NULL,
      meta TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Email verifications
  db.run(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Requests (topup/withdraw)
  db.run(`
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,          -- topup | withdraw
      amount REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
      note TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Admins
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'owner', -- owner | service | viewer
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
  `);

  // Top-Up PINs (6-digit numeric, short-lived)
  db.run(`
    CREATE TABLE IF NOT EXISTS topup_pins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      pin TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_topup_pins_user_revoked_expires ON topup_pins(user_id, revoked, expires_at);`);

  // Saved Recipients
  db.run(`
    CREATE TABLE IF NOT EXISTS saved_recipients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_user_id INTEGER NOT NULL,
      recipient_user_id INTEGER,
      recipient_account TEXT NOT NULL,
      nickname TEXT NOT NULL DEFAULT '',
      is_favorite INTEGER NOT NULL DEFAULT 0,
      times_used INTEGER NOT NULL DEFAULT 0,
      total_sent REAL NOT NULL DEFAULT 0,
      is_deleted INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      last_used_at TEXT,
      FOREIGN KEY(owner_user_id) REFERENCES users(id),
      FOREIGN KEY(recipient_user_id) REFERENCES users(id)
    );
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_sr_owner ON saved_recipients(owner_user_id, is_deleted);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_sr_account ON saved_recipients(recipient_account);`);

  // Seed first admin if none
  db.get(`SELECT COUNT(*) AS cnt FROM admins`, async (e, r) => {
    if (e) return;
    if ((r?.cnt || 0) === 0) {
      const u = process.env.ADMIN_USER || "owner";
      const p = process.env.ADMIN_PASS || "Owner@12345";
      const hash = await bcrypt.hash(p, 10);
      const created_at = new Date().toISOString();
      db.run(
        `INSERT INTO admins (username, password_hash, role, is_active, created_at) VALUES (?, ?, 'owner', 1, ?)`,
        [u, hash, created_at],
        (err2) => {
          if (err2) console.error("❌ Seed admin error:", err2.message);
          else console.log(`✅ Seeded admin user "${u}"`);
        }
      );
    }
  });
});

// Ensure 'pin_hash' column exists in users table
const ensureColumn = (table, column, type) => {
  db.all(`PRAGMA table_info(${table})`, (err, rows) => {
    if (err) return;
    if (!Array.isArray(rows)) return; // ✅ نحمي من null
    const exists = rows.some(r => r.name === column);
    if (!exists) {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
  });
};
ensureColumn('users', 'pin_hash', 'TEXT');
ensureColumn('users', 'pin_fail_count', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'pin_reset_required', 'INTEGER NOT NULL DEFAULT 0');

// ====== Utils ======
const isLibyanPhone = (p) => /^0(91|92|93|94)\d{7}$/.test(String(p || "").trim());
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e || "").trim());
const isStrongPassword = (p) =>
  /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && String(p || "").length >= 8;

function cleanStr(s) {
  return String(s || "").replace(/\u0000/g, "").trim().slice(0, 200);
}
const nowISO = () => new Date().toISOString();
const addMinutesISO = (mins) => new Date(Date.now() + mins * 60 * 1000).toISOString();
const addSecondsISO = (sec) => new Date(Date.now() + sec * 1000).toISOString();

async function sendVerifyEmail({ to, name, code, link }) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.warn("⚠️ بريد التفعيل غير مُفعّل: GMAIL_USER/GMAIL_APP_PASSWORD غير موجودة");
    return;
  }
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;max-width:560px;margin:auto">
      <h2 style="color:#111827">مرحبًا ${name || ""}</h2>
      <p>شكرًا لتسجيلك في Floosy. استخدم كود التحقق التالي:</p>
      <div style="font-size:28px;font-weight:800;letter-spacing:4px;padding:12px 16px;background:#0f172a;color:#22c55e;border-radius:12px;text-align:center">${code}</div>
      <p>أو اضغط على الرابط لتأكيد بريدك:</p>
      <p><a href="${link}" style="background:#22c55e;color:#0b1220;padding:10px 14px;border-radius:10px;text-decoration:none;font-weight:700">تأكيد البريد الآن</a></p>
      <p style="color:#6b7280;font-size:12px">الرابط صالح لمدة 15 دقيقة.</p>
    </div>
  `;
  await transporter.sendMail({ from: `Floosy <${MAIL_FROM}>`, to, subject: "تأكيد بريدك الإلكتروني", html });
}
function maskName(full) {
  const s = String(full || '').trim();
  if (!s) return 'مستخدم';
  const parts = s.split(/\s+/);
  const first = parts[0] || '';
  if (first.length <= 2) return first + '…';
  return first.slice(0, Math.min(3, first.length)) + '…';
}
function phoneLast2(p) {
  const s = String(p || '').replace(/\D/g,'');
  return s.slice(-2);
}
function normalizeAccount(acc) {
  return String(acc || '').trim().toUpperCase().replace(/\s+/g,'');
}

// ====== JWT Middlewares ======
function requireUserAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) {
    const cookie = getCookie(req, "floosy_token");
    if (cookie) token = cookie;
  }
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireCsrfIfCookie(req, res, next) {
  const hasBearer = (req.headers.authorization || "").startsWith("Bearer ");
  if (hasBearer) return next();

  const header = String(req.headers["x-csrf-token"] || "");
  const userCsrf  = getCookie(req, "csrf_token");
  const adminCsrf = getCookie(req, "admin_csrf");

  if (!header) return res.status(403).json({ error: "CSRF validation failed" });

  if ((userCsrf && header === userCsrf) || (adminCsrf && header === adminCsrf)) {
    return next();
  }

  return res.status(403).json({ error: "CSRF validation failed" });
}

// ====== Admin session ======
function signAdminToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2d" });
}

async function adminFromToken(req) {
  const tok = getCookie(req, "floosy_admin");
  if (!tok) return null;
  try {
    const data = jwt.verify(tok, JWT_SECRET);
    if (data?.typ !== "admin") return null;
    return data;
  } catch { return null; }
}

function requireAdmin(req, res, next) {
  (async () => {
    if (!ipAllowed(req)) return res.status(403).json({ error: "IP not allowed" });

    if (ADMIN_DEVICE_ENFORCE) {
      const dev = getCookie(req, "admin_device");
      const must = signDevice(req.headers["user-agent"] || "");
      if (!dev || !must || dev !== must) {
        return res.status(403).json({ error: "Device not bound" });
      }
    }

    const session = await adminFromToken(req);
    if (!session) return res.status(401).json({ error: "Admin auth required" });

    db.get(
      `SELECT id, username, role, is_active FROM admins WHERE id = ?`,
      [session.aid],
      (e, row) => {
        if (e) return res.status(500).json({ error: "DB error" });
        if (!row || Number(row.is_active) !== 1) return res.status(403).json({ error: "Admin disabled" });
        req.admin = { id: row.id, username: row.username, role: row.role };
        next();
      }
    );
  })();
}

function adminGate(req, res, next) {
  requireAdmin(req, res, (err) => {
    if (err) return; // already responded
    next();
  });
}

// ====== Pages (gated before static) ======
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/register", (_req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/verify", (_req, res) => res.sendFile(path.join(__dirname, "public", "verify.html")));
app.get("/login", (_req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/dashboard", (_req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/services", (_req, res) => res.sendFile(path.join(__dirname, "public", "services.html")));
app.get("/services-login", (_req, res) => res.sendFile(path.join(__dirname, "public", "services-login.html")));
app.get("/features", (_req, res) => res.sendFile(path.join(__dirname, "public", "features.html")));
app.get("/contact", (_req, res) => res.sendFile(path.join(__dirname, "public", "contact.html")));
// Admin pages
app.get("/admin-login", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin-login.html")));
app.get("/admin-login.html", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin-login.html")));
app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/admin.html", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

// Static AFTER page routes
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h", etag: true }));

// ====== Force HTTPS in prod ======
app.use((req, res, next) => {
  const isProd = process.env.NODE_ENV === "production";
  const proto = (req.headers["x-forwarded-proto"] || "").toString();
  if (isProd && proto && proto !== "https") {
    return res.redirect(301, "https://" + req.headers.host + req.originalUrl);
  }
  next();
});

// ====== User Auth ======

// POST /logout (خارج أي مسار آخر)
app.post('/logout', requireUserAuth, requireCsrfIfCookie, (req, res) => {
  setCookie(res, 'floosy_token', '', { maxAge: 0 });
  setReadableCookie(res, 'csrf_token', '', { maxAge: 0 });
  res.json({ ok: true });
});

// POST /check-pin — التأكد من الـPIN أثناء الدخول
app.post('/check-pin', requireUserAuth, async (req, res) => {
  const pin = String(req.body.pin || '').trim();
  if (!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'PIN غير صالح' });

  db.get(`SELECT pin_hash, pin_fail_count, pin_reset_required FROM users WHERE id=?`, [req.user.id], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row || !row.pin_hash) return res.status(400).json({ error: 'لم تقم بتعيين PIN بعد' });

    if (Number(row.pin_reset_required) === 1) {
      return res.status(423).json({ error: 'تجاوزت الحد. يرجى إعادة تعيين الـ PIN عبر البريد.' });
    }

    const ok = await bcrypt.compare(pin, row.pin_hash);
    if (!ok) {
      const fails = Number(row.pin_fail_count || 0) + 1;
      if (fails >= 10) {
        db.run(`UPDATE users SET pin_fail_count=0, pin_reset_required=1 WHERE id=?`, [req.user.id], () => {
          return res.status(423).json({ error: 'تجاوزت الحد. يرجى إعادة تعيين الـ PIN عبر البريد.' });
        });
      } else {
        db.run(`UPDATE users SET pin_fail_count=? WHERE id=?`, [fails, req.user.id], () => {
          return res.status(401).json({ error: 'رمز PIN غير صحيح' });
        });
      }
      return;
    }

    // success
    db.run(`UPDATE users SET pin_fail_count=0 WHERE id=?`, [req.user.id], () => res.json({ ok: true }));
  });
});

// ---- register Step 1: send OTP ----
app.post('/register-send-otp', async (req, res) => {
  const { email, phone, password } = req.body || {};
  if (!isValidEmail(email)) return res.status(400).json({ error: "بريد غير صالح" });
  if (!isLibyanPhone(phone)) return res.status(400).json({ error: "هاتف غير صالح" });
  if (!isStrongPassword(password)) return res.status(400).json({ error: "كلمة مرور ضعيفة" });

  db.get(`SELECT id FROM users WHERE email=?`, [email.toLowerCase()], (e, row)=>{
    if (e) return res.status(500).json({ error: "DB error" });
    if (row) return res.status(409).json({ error: "البريد مستخدم" });

    const emailNorm = String(email).toLowerCase().trim();
    const cooldownSec = OTP_SEND_COOLDOWN_SEC_DEFAULT;
    const can = canSendOtp(emailNorm, cooldownSec);
    if (!can.ok) {
      return res.json({ ok: true });
    }

    const code = String(crypto.randomInt(100000,999999));
    const now = new Date().toISOString();
    const expires = addSecondsISO(OTP_CODE_TTL_SEC);
    db.run(`INSERT INTO email_verifications (user_id,email,code,expires_at,created_at,used)
            VALUES (0,?,?,?, ?,0)`,
      [emailNorm, code, expires, now], async (err2)=>{
        if(err2) return res.status(500).json({ error: "فشل الإرسال" });
        try{
          await sendVerifyEmail({to:emailNorm,name:"",code,link:""});
        } catch{}
        markSentOtp(can.k, can.rec, can.now);
        return res.json({ ok:true });
      });
  });
});

// ---- Step 2: verify OTP ----
app.post(
  '/register-verify-otp',
  verifyOtpGuard, // ✅ يفحص الحد اليومي حسب (email+IP+اليوم)
  (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const otp   = String(req.body.otp   || '').trim();
    if (!email || !otp) return res.status(400).json({ error: "بيانات ناقصة" });

    const ip = clientIp(req);

    db.get(
      `SELECT id, code, expires_at, used
       FROM email_verifications
       WHERE email = ?
       ORDER BY id DESC
       LIMIT 1`,
      [email],
      (err, row) => {
        if (err)   return res.status(500).json({ error: "DB error" });
        if (!row || row.used || new Date(row.expires_at) < new Date() || row.code !== otp) {
          recordOtpWrong(email, ip);
          return res.status(400).json({ error: "الكود غير صحيح أو منتهي الصلاحية" });
        }

        db.run(`UPDATE email_verifications SET used=1 WHERE id=?`, [row.id], () => {
          resetOtpWrong(email, ip);
          return res.json({ ok: true, name: "" });
        });
      }
    );
  }
);

// ---- Step 3: finish - create user + set PIN ----
app.post('/register-pin', async (req,res)=>{
  const { email, pin }=req.body||{};
  const { phone,password }=req.body||{};
  if(!email||!pin) return res.status(400).json({ error:"بيانات ناقصة" });
  db.get(`SELECT id FROM users WHERE email=?`, [email], async(e,row)=>{
    if(e) return res.status(500).json({ error:"DB" });
    if(row) return res.status(409).json({ error:"مستخدم موجود" });

    const hash = await bcrypt.hash(password,10);
    const created = nowISO();
    db.run(`INSERT INTO users(full_name,phone,email,password_hash,balance,created_at,email_verified,is_active) VALUES(?,?,?, ?,0,?,1,1)`,
    ["", phone, email.toLowerCase(), hash, created], function(err2){
      if(err2) return res.status(500).json({ error:"DB" });
      return res.json({ ok:true });
    });
  });
});

// ====== Unified Register/Login ======
app.post(
  "/register",
  authLimiter,
  body("full_name").trim().isLength({ min: 2, max: 100 }).escape().withMessage("الاسم قصير"),
  body("phone").custom(isLibyanPhone).withMessage("رقم هاتف ليبي غير صحيح"),
  body("email").custom(isValidEmail).withMessage("بريد إلكتروني غير صالح"),
  body("password").custom(isStrongPassword).withMessage("كلمة مرور ضعيفة"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const data = matchedData(req);
    const full_name = cleanStr(data.full_name);
    const phone = data.phone.trim();
    const email = cleanStr(data.email).toLowerCase();
    const password = String(req.body.password || "");

    const created_at = new Date().toISOString();
    const password_hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (full_name, phone, email, password, password_hash, balance, created_at, email_verified, is_active, allow_services)
       VALUES (?, ?, ?, '', ?, 0, ?, 0, 1, 0)`,
      [full_name, phone, email, password_hash, created_at],
      function (err) {
        if (err) {
          if (String(err).includes("UNIQUE")) {
            const field = String(err).includes("phone") ? "رقم الهاتف" : "البريد";
            return res.status(409).json({ error: `${field} مستخدم من قبل` });
          }
          return res.status(500).json({ error: "خطأ الخادم" });
        }

        const userId = this.lastID;
        const token = jwt.sign({ id: userId, phone }, JWT_SECRET, { expiresIn: "7d" });

        setCookie(res, "floosy_token", token, { maxAge: 7 * 24 * 60 * 60 * 1000 });
        const csrf = crypto.randomBytes(16).toString("hex");
        setReadableCookie(res, "csrf_token", csrf, { maxAge: 7 * 24 * 60 * 60 * 1000 });

        // Send email verify code (fire-and-forget)
        (async () => {
          try {
            const emailNorm = email;
            const cooldownSec = OTP_SEND_COOLDOWN_SEC_DEFAULT;
            const can = canSendOtp(emailNorm, cooldownSec);
            if (!can.ok) return;

            const code = String(crypto.randomInt(100000, 999999));
            const now = new Date();
            const expires = new Date(now.getTime() + OTP_CODE_TTL_SEC * 1000).toISOString();
            const created = now.toISOString();
            db.run(
              `INSERT INTO email_verifications (user_id, email, code, expires_at, created_at, used) VALUES (?, ?, ?, ?, ?, 0)`,
              [userId, emailNorm, code, expires, created],
              async (e2) => {
                if (e2) return console.error("Email code save error:", e2.message);
                const link = `${APP_BASE_URL}/verify-email?code=${encodeURIComponent(code)}&email=${encodeURIComponent(emailNorm)}`;
                await sendVerifyEmail({ to: emailNorm, name: full_name, code, link });
                markSentOtp(can.k, can.rec, can.now);
              }
            );
          } catch (e) {
            console.error("Send email error:", e.message);
          }
        })();

        res.json({ user: { id: userId, full_name, phone, email, balance: 0, allow_services: 0 }, token, csrf });
      }
    );
  }
);

app.post(
  "/login",
  authLimiter,
  body("email").custom(isValidEmail).withMessage("بريد إلكتروني غير صالح"),
  body("password").isLength({ min: 1 }).withMessage("كلمة مرور مطلوبة"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "بيانات غير صحيحة" });

    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    // lock
    const key = `U:${email}`;
    if (checkLock(key)) {
      return res.status(429).json({ error: "محاولات كثيرة. جرّب لاحقًا." });
    }

    db.get(
      `SELECT id, full_name, phone, email, balance, password, password_hash, is_active, email_verified, allow_services
       FROM users WHERE email = ?`,
      [email],
      async (err, row) => {
        if (err) return res.status(500).json({ error: "خطأ الخادم" });
        const invalidMsg = { error: "بيانات غير صحيحة" };

        if (!row) { recordFail(key); return res.status(401).json(invalidMsg); }
        if (Number(row.is_active) !== 1) return res.status(403).json({ error: "الحساب موقوف. تواصل مع الإدارة." });

        const ok = row.password_hash ? await bcrypt.compare(password, row.password_hash) : false;

        if (!ok) { recordFail(key); return res.status(401).json(invalidMsg); }

        recordSuccess(key);

        const token = jwt.sign({ id: row.id, email: row.email }, JWT_SECRET, { expiresIn: "7d" });
        setCookie(res, "floosy_token", token, { maxAge: 7 * 24 * 60 * 60 * 1000 });
        const csrf = crypto.randomBytes(16).toString("hex");
        setReadableCookie(res, "csrf_token", csrf, { maxAge: 7 * 24 * 60 * 60 * 1000 });

        const { id, full_name, email: em, balance, allow_services, email_verified } = row;
        res.json({ user: { id, full_name, phone: row.phone, email: em, balance, allow_services, email_verified }, token, csrf });
      }
    );
  }
);

// ====== Email Verify ======
app.post(
  "/resend-verify",
  otpLimiter,
  body("email").custom(isValidEmail).withMessage("بريد غير صالح"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const email = String(req.body.email || "").toLowerCase().trim();
    db.get(`SELECT id, full_name FROM users WHERE email = ?`, [email], (e1, u) => {
      if (e1) return res.status(500).json({ error: "خطأ الخادم" });
      if (!u) { console.log("resend-verify: email not found", email); return res.json({ ok: true }); }

      const emailNorm = email;
      const cooldownSec = OTP_SEND_COOLDOWN_SEC_DEFAULT;
      const can = canSendOtp(emailNorm, cooldownSec);
      if (!can.ok) {
        return res.json({ ok: true });
      }

      const code = String(crypto.randomInt(100000, 999999));
      const now = new Date();
      const expires = new Date(now.getTime() + OTP_CODE_TTL_SEC * 1000).toISOString();
      const created = now.toISOString();

      db.run(
        `INSERT INTO email_verifications (user_id, email, code, expires_at, created_at, used)
         VALUES (?, ?, ?, ?, ?, 0)`,
        [u.id, emailNorm, code, expires, created],
        async (e2) => {
          if (e2) return res.status(500).json({ error: "تعذّر حفظ كود جديد" });
          const link = `${APP_BASE_URL}/verify-email?code=${encodeURIComponent(code)}&email=${encodeURIComponent(emailNorm)}`;
          try { await sendVerifyEmail({ to: emailNorm, name: u.full_name, code, link }); } catch {}
                    markSentOtp(can.k, can.rec, can.now);
          markSentOtp(can.k, can.rec, can.now);
          return res.json({ ok: true });
        }
      );
    });
  }
);

// ===== Change email while pending =====
app.post(
  "/change-email",
  body("old_email").custom(isValidEmail).withMessage("old_email غير صالح"),
  body("new_email").custom(isValidEmail).withMessage("new_email غير صالح"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const old_email = String(req.body.old_email || "").trim().toLowerCase();
    const new_email = String(req.body.new_email || "").trim().toLowerCase();

    if (old_email === new_email) {
      return res.status(400).json({ error: "البريد الجديد يطابق البريد الحالي" });
    }

    db.get(
      `SELECT id, full_name, email_verified FROM users WHERE email = ? LIMIT 1`,
      [old_email],
      (e1, u) => {
        if (e1) return res.status(500).json({ error: "DB error (lookup old_email)" });
        if (!u) { console.log("change-email: old not found", old_email); return res.json({ ok: true }); }
        if (Number(u.email_verified) === 1) {
          return res.status(400).json({ error: "لا يمكن تغيير البريد لحساب مُفعّل" });
        }

        db.get(
          `SELECT id FROM users WHERE email = ? LIMIT 1`,
          [new_email],
          (e2, ex) => {
            if (e2) return res.status(500).json({ error: "DB error (check new_email)" });
            if (ex && ex.id !== u.id) {
              return res.status(409).json({ error: "البريد الجديد مستخدم من قبل" });
            }

            db.run(
              `UPDATE users SET email = ?, email_verified = 0 WHERE id = ?`,
              [new_email, u.id],
              (e3) => {
                if (e3) return res.status(500).json({ error: "DB error (update email)" });

                const emailNorm = new_email;
                const cooldownSec = OTP_SEND_COOLDOWN_SEC_DEFAULT;
                const can = canSendOtp(emailNorm, cooldownSec);
                if (!can.ok) {
                  return res.json({ ok: true, email: new_email });
                }

                const code = String(crypto.randomInt(100000, 999999));
                const now = new Date();
                const expires = new Date(now.getTime() + OTP_CODE_TTL_SEC * 1000).toISOString();
                const created = now.toISOString();

                db.run(
                  `INSERT INTO email_verifications (user_id, email, code, expires_at, created_at, used)
                   VALUES (?, ?, ?, ?, ?, 0)`,
                  [u.id, emailNorm, code, expires, created],
                  async (e4) => {
                    if (e4) return res.status(500).json({ error: "تعذّر حفظ كود جديد" });

                    const link = `${APP_BASE_URL}/verify-email?code=${encodeURIComponent(code)}&email=${encodeURIComponent(emailNorm)}`;
                    try { await sendVerifyEmail({ to: emailNorm, name: u.full_name, code, link }); } catch {}
                    markSentOtp(can.k, can.rec, can.now);

                    return res.json({ ok: true, email: new_email });
                  }
                );
              }
            );
          }
        );
      }
    );
  }
);

app.get("/verify-email", verifyOtpGuard, (req, res) => {
  const code = String(req.query.code || "").trim();
  const email = String(req.query.email || "").trim().toLowerCase();
  if (!code || !email) return res.status(400).send("رابط غير صالح");

  const ip = clientIp(req);
  db.get(
    `SELECT ev.id, ev.user_id, ev.expires_at, ev.used
     FROM email_verifications ev
     WHERE ev.email = ? AND ev.code = ?
     ORDER BY ev.id DESC LIMIT 1`,
    [email, code],
    (err, row) => {
      if (err) return res.status(500).send("خطأ الخادم");
      if (!row || row.used || new Date(row.expires_at).getTime() < Date.now()) {
        recordOtpWrong(email, ip);
        return res.status(400).json({ error: "الكود غير صحيح أو منتهي الصلاحية" });
      }

      db.serialize(() => {
        db.run(`UPDATE users SET email_verified = 1 WHERE id = ?`, [row.user_id]);
        db.run(`UPDATE email_verifications SET used = 1 WHERE id = ?`, [row.id]);
      });

      resetOtpWrong(email, ip);
      res.send(`<!doctype html><meta charset="utf-8"/>
        <div style="font-family:system-ui;display:grid;place-items:center;min-height:100vh;background:#0f172a;color:#e5e7eb">
          <div style="background:#111827;border:1px solid rgba(148,163,184,.15);padding:24px;border-radius:12px;text-align:center;max-width:460px">
            <h2 style="margin:0 0 8px">تم تأكيد بريدك ✅</h2>
            <p style="color:#94a3b8">يمكنك الآن إغلاق هذه الصفحة والعودة للتطبيق.</p>
            <a href="/dashboard.html" style="display:inline-block;margin-top:10px;background:#22c55e;color:#062b1a;padding:10px 14px;border-radius:10px;text-decoration:none;font-weight:700">الذهاب للوحة</a>
          </div>
        </div>`);
    }
  );
});
// ====== Login/OTP lock helpers (updated) ======
const failedLogins = new Map();

// Wrong OTP verifies per (email|ip|day)
const otpWrongAttempts = new Map();
// OTP sends per (email|day)
const otpSendCounter  = new Map();

function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || '';
}
function dayKey(){ return new Date().toISOString().slice(0,10); }
function keyWrong(email, ip){ return `${String(email||'').toLowerCase().trim()}|${ip}|${dayKey()}`; }
function keySend(email){ return `${String(email||'').toLowerCase().trim()}|${dayKey()}`; }

function getOtpWrong(email, ip){ return Number(otpWrongAttempts.get(keyWrong(email, ip)) || 0); }
function recordOtpWrong(email, ip){
  const k = keyWrong(email, ip);
  otpWrongAttempts.set(k, getOtpWrong(email, ip) + 1);
}
function resetOtpWrong(email, ip){ otpWrongAttempts.delete(keyWrong(email, ip)); }

function canSendOtp(email, cooldownSec){
  const k = keySend(email);
  const rec = otpSendCounter.get(k) || { count:0, lastSentAtMs:0 };
  const now = Date.now();
  const cooldownOk = (now - rec.lastSentAtMs) >= (cooldownSec*1000);
  return { ok: rec.count < OTP_SEND_DAILY_MAX && cooldownOk, k, rec, now };
}
function markSentOtp(k, rec, now){
  otpSendCounter.set(k, { count: (rec.count || 0) + 1, lastSentAtMs: now });
}

function checkLock(key) {
  const now = Date.now();
  const rec = failedLogins.get(key);
  if (!rec) return false;
  if (rec.until && rec.until > now) return true;
  if (rec.until && rec.until <= now) failedLogins.delete(key);
  return false;
}
function recordFail(key) {
  const now = Date.now();
  const rec = failedLogins.get(key) || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= 5) { rec.until = now + 15 * 60 * 1000; rec.count = 0; }
  failedLogins.set(key, rec);
}
function recordSuccess(key) { failedLogins.delete(key); }

// Guard before OTP verification (per request)
function verifyOtpGuard(req, res, next) {
  const email = String(req.body?.email || req.query?.email || '').toLowerCase().trim();
  const ip = clientIp(req);
  if (email && getOtpWrong(email, ip) >= OTP_VERIFY_DAILY_WRONG_MAX) {
    return res.status(429).json({ error: "محاولات كثيرة اليوم. حاول غدًا أو اطلب كود جديد." });
  }
  next();
}

// ====== Email Verify (POST, JSON) ======
app.post(
  "/verify-email",
  verifyOtpGuard,
  body("email").custom(isValidEmail).withMessage("بريد غير صالح"),
  body("code").isLength({ min: 4 }).withMessage("كود غير صالح"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const email = String(req.body.email || "").toLowerCase().trim();
    const code  = String(req.body.code  || "").trim();
    const ip = clientIp(req);

    db.get(
      `SELECT ev.id, ev.user_id, ev.email, ev.expires_at, ev.used
       FROM email_verifications ev
       WHERE ev.email = ? AND ev.code = ?
       ORDER BY ev.id DESC LIMIT 1`,
      [email, code],
      (err, row) => {
        if (err)   return res.status(500).json({ error: "خطأ الخادم" });
        if (!row || row.used || new Date(row.expires_at).getTime() < Date.now()) {
          recordOtpWrong(email, ip);
          return res.status(400).json({ error: "الكود غير صحيح أو منتهي الصلاحية" });
        }

        const fetchUserAndFinish = (userIdOrNull) => {
          const finishWithUser = (u) => {
            db.serialize(() => {
              if (u?.id) db.run(`UPDATE users SET email_verified = 1 WHERE id = ?`, [u.id]);
              db.run(`UPDATE email_verifications SET used = 1 WHERE id = ?`, [row.id], (e2) => {
                if (e2) return res.status(500).json({ error: "خطأ أثناء التحديث" });
                if (!u) return res.status(404).json({ error: "المستخدم غير موجود بعد التفعيل" });

                const token = jwt.sign({ id: u.id, phone: u.phone }, JWT_SECRET, { expiresIn: "7d" });
                setCookie(res, "floosy_token", token, { maxAge: 7 * 24 * 60 * 60 * 1000 });
                const csrf = crypto.randomBytes(16).toString("hex");
                setReadableCookie(res, "csrf_token", csrf, { maxAge: 7 * 24 * 60 * 60 * 1000 });

                const needPin = !u.pin_hash;
                resetOtpWrong(email, ip);
                return res.json({ ok: true, set_pin: needPin, token, csrf, user: {
                  id: u.id, full_name: u.full_name, phone: u.phone, email: u.email,
                  balance: u.balance, allow_services: u.allow_services, email_verified: u.email_verified
                }});
              });
            });
          };

          if (Number.isFinite(userIdOrNull) && userIdOrNull > 0) {
            db.get(
              `SELECT id, full_name, phone, email, balance, allow_services, email_verified, pin_hash
               FROM users WHERE id = ?`,
              [userIdOrNull],
              (e3, u) => {
                if (e3) return res.status(500).json({ error: "المستخدم غير موجود بعد التفعيل" });
                if (u) return finishWithUser(u);
                db.get(
                  `SELECT id, full_name, phone, email, balance, allow_services, email_verified, pin_hash
                   FROM users WHERE email = ?`,
                  [email],
                  (_e4, u2) => finishWithUser(u2 || null)
                );
              }
            );
          } else {
            db.get(
              `SELECT id, full_name, phone, email, balance, allow_services, email_verified, pin_hash
               FROM users WHERE email = ?`,
              [email],
              (_e5, u) => finishWithUser(u || null)
            );
          }
        };

        fetchUserAndFinish(Number(row.user_id) || null);
      }
    );
  }
);

// ===== Forgot Password =====
app.post("/forgot-password/send-otp", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "بريد غير صالح" });
  }
  db.get(`SELECT id, full_name FROM users WHERE email = ?`, [email], async (e, row) => {
    if (e) return res.status(500).json({ error: "DB error" });
    if (!row) { console.log("forgot-password: email not found", email); return res.json({ ok: true }); }

    const emailNorm = email;
    const cooldownSec = OTP_SEND_COOLDOWN_SEC_FORGOT_PW;
    const can = canSendOtp(emailNorm, cooldownSec);
    if (!can.ok) {
      return res.json({ ok: true });
    }

    const code = String(crypto.randomInt(100000, 999999));
    const expires = addSecondsISO(OTP_CODE_TTL_SEC);
    const created = nowISO();

    db.run(
      `INSERT INTO email_verifications (user_id,email,code,expires_at,created_at,used)
       VALUES (?, ?, ?, ?, ?, 0)`,
      [row.id, emailNorm, code, expires, created],
      async (err2) => {
        if (err2) return res.status(500).json({ error: "فشل الإرسال" });
        try {
          await sendVerifyEmail({ to: emailNorm, name: row.full_name, code, link: "" });
        } catch {}
        markSentOtp(can.k, can.rec, can.now);
        return res.json({ ok: true });
      }
    );
  });
});

app.post('/forgot-pin/verify-otp', verifyOtpGuard, (req,res)=>{
  const email = String(req.body.email || "").trim().toLowerCase();
  const otp   = String(req.body.otp   || "").trim();
  if (!email || !otp) return res.status(400).json({ error:"بيانات ناقصة" });

  const ip = clientIp(req);

  db.get(
    `SELECT id, code, expires_at, used 
     FROM email_verifications
     WHERE email=? 
     ORDER BY id DESC LIMIT 1`,
    [email],
    (err,row)=>{
      if(err) return res.status(500).json({ error:"DB error" });
      if(!row || row.used || new Date(row.expires_at) < new Date() || row.code !== otp) {
        recordOtpWrong(email, ip);
        return res.status(400).json({ error:"الكود غير صحيح أو منتهي الصلاحية" });
      }

      db.run(`UPDATE email_verifications SET used=1 WHERE id=?`, [row.id], ()=>{
        resetOtpWrong(email, ip);
        return res.json({ ok:true });
      });
  });
});

app.post('/forgot-password/reset', async (req, res) => {
  const { email, new_password } = req.body || {};
  if (!email || !new_password) {
    return res.status(400).json({ error: "بيانات ناقصة" });
  }
  const strong = /[a-z]/.test(new_password) && /[A-Z]/.test(new_password) && /\d/.test(new_password) && new_password.length >= 8;
  if (!strong) {
    return res.status(400).json({ error: "كلمة المرور ضعيفة" });
  }

  db.get(`SELECT id FROM users WHERE email = ?`, [email.toLowerCase()], async (e, row) => {
    if (e)   return res.status(500).json({ error: "DB error" });
    if (!row) return res.status(404).json({ error: "المستخدم غير موجود" });

    const hash = await bcrypt.hash(new_password, 10);
    db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hash, row.id], (e2) => {
      if (e2) return res.status(500).json({ error: "فشل التحديث" });
      return res.json({ ok: true });
    });
  });
});

// ========== Forgot PIN (موحّد) ==========
app.post("/forgot-pin/send-otp", requireUserAuth, async (req, res) => {
  const userId = req.user.id;
  db.get(`SELECT email, full_name FROM users WHERE id=?`, [userId], async (e, u) => {
    if (e || !u) return res.status(400).json({ error: "مستخدم غير موجود" });

    const emailNorm = u.email.toLowerCase();
    const cooldownSec = OTP_SEND_COOLDOWN_SEC_DEFAULT;
    const can = canSendOtp(emailNorm, cooldownSec);
    if (!can.ok) {
      return res.json({ ok: true });
    }

    const code = String(crypto.randomInt(100000, 999999));
    const now = new Date();
    const expires = new Date(now.getTime() + OTP_CODE_TTL_SEC * 1000).toISOString();
    const created = now.toISOString();

    db.run(
      `INSERT INTO email_verifications (user_id, email, code, expires_at, created_at, used)
       VALUES (?, ?, ?, ?, ?, 0)`,
      [userId, emailNorm, code, expires, created],
      async (e2) => {
        if(e2) return res.status(500).json({ error: "تعذر الإرسال" });
        try{ await sendVerifyEmail({to:emailNorm,name:u.full_name,code,link:""}) }catch{}
        markSentOtp(can.k, can.rec, can.now);
        return res.json({ ok:true });
      }
    );
  });
});

app.post("/forgot-pin/verify", verifyOtpGuard, requireUserAuth, async (req,res)=>{
  const {otp} = req.body||{};
  db.get(
    `SELECT id,email,code,expires_at,used FROM email_verifications
      WHERE user_id=? ORDER BY id DESC LIMIT 1`,
    [req.user.id], (e,row)=>{
      if(e) return res.status(500).json({error:"DB"});
      const email = String(row?.email || "").toLowerCase();
      const ip = clientIp(req);
      if(!row || row.used || row.code!==String(otp) || new Date(row.expires_at)<new Date()) {
        recordOtpWrong(email, ip);
        return res.status(400).json({error:"الكود غير صحيح أو منتهي الصلاحية"});
      }
      db.run(`UPDATE email_verifications SET used=1 WHERE id=?`, [row.id], ()=>{
        resetOtpWrong(email, ip);
        res.json({ok:true});
      });
    });
});

// ====== Set Login PIN ======
app.post("/set-pin", requireUserAuth, requireCsrfIfCookie, async (req, res) => {
  const pin = String(req.body.pin || "").trim();
  if (!/^\d{6}$/.test(pin)) return res.status(400).json({ error: "PIN غير صالح" });

  const hash = await bcrypt.hash(pin, 10);
  db.run(
    `UPDATE users SET pin_hash=?, pin_fail_count=0, pin_reset_required=0 WHERE id=?`,
    [hash, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: "تعذّر الحفظ" });
      res.json({ ok: true });
    }
  );
});

// ====== Basic account APIs ======
app.get("/user/by-phone/:phone", (req, res) => {
  const phone = String(req.params.phone || "");
  db.get(
    `SELECT id, full_name, phone, email, balance, created_at FROM users WHERE phone = ?`,
    [phone],
    (err, row) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      if (!row) return res.status(404).json({ error: "المستخدم غير موجود" });
      res.json(row);
    }
  );
});

app.get("/me", requireUserAuth, (req, res) => {
  db.get(
    `SELECT id, full_name, phone, email, balance, created_at, email_verified, is_active, allow_services
     FROM users WHERE id = ?`,
    [req.user.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      if (!row) return res.status(404).json({ error: "المستخدم غير موجود" });
      res.json(row);
    }
  );
});

app.post("/account-lookup", requireUserAuth, requireCsrfIfCookie, (req, res) => {
  // طبّع الإدخال: شِل الشرطات والفراغات والبادئة LY-
  const input = String(req.body.account || '').toUpperCase().trim();
  const accNorm = input.replace(/\s+/g, '').replace(/^LY-?/, '').replace(/-/g, '');

  db.get(
    `SELECT id, full_name, phone, account_number
     FROM users
     WHERE REPLACE(UPPER(REPLACE(account_number, 'LY-', '')), '-', '') = ?
     LIMIT 1`,
    [accNorm],
    (e, row) => {
      if (e) return res.status(500).json({ error: "خطأ الخادم" });
      if (!row) { console.log("forgot-password: email not found", email); return res.json({ ok: true }); }
      if (row.id === req.user.id) return res.status(400).json({ error: "لا يمكنك التحويل لنفسك" });

      return res.json({
        user_id: row.id,
        account: row.account_number,
        display_name: maskName(row.full_name),
        phone_hint: phoneLast2(row.phone)
      });
    }
  );
});

// ====== Account Number (generate if missing) ======
function genAccountNumberString() {
  const n = String(crypto.randomInt(0, 99999999)).padStart(8, "0");
  return `LY-${n.slice(0,4)}-${n.slice(4)}`; // LY بدل LYD
}
function assignAccountNumberIfMissing(userId, cb) {
  db.get(`SELECT account_number FROM users WHERE id=?`, [userId], (e, r) => {
    if (e) return cb(e);
    if (r?.account_number) return cb(null, r.account_number);
    // generate unique
    const tryOnce = () => {
      const acc = genAccountNumberString();
      db.get(`SELECT 1 FROM users WHERE account_number = ?`, [acc], (e2, x) => {
        if (e2) return cb(e2);
        if (x) return tryOnce();
        db.run(`UPDATE users SET account_number=? WHERE id=?`, [acc, userId], (e3) => {
          if (e3) return cb(e3);
          cb(null, acc);
        });
      });
    };
    tryOnce();
  });
}

app.get("/account-number", requireUserAuth, (req, res) => {
  assignAccountNumberIfMissing(req.user.id, (e, acc) => {
    if (e) return res.status(500).json({ error: "تعذّر توليد الرقم" });
    res.json({ account_number: acc });
  });
});

// ====== Top-up PIN APIs ======
// إرجاع الـ PIN النشط (إن وجد)
app.get("/topup-pin", requireUserAuth, (req, res) => {
  const nowISO = new Date().toISOString();
  db.get(
    `SELECT id, pin, expires_at
     FROM topup_pins
     WHERE user_id = ? AND revoked = 0 AND expires_at > ?
     ORDER BY id DESC LIMIT 1`,
    [req.user.id, nowISO],
    (e, row) => {
      if (e) return res.status(500).json({ error: "DB error" });
      if (!row) return res.status(404).json({}); // لا يوجد PIN نشط
      return res.json({ pin: row.pin, expires_at: row.expires_at });
    }
  );
});

// توليد PIN جديد: لو فيه نشط يرجّع نفس القديم (منع سبام)
app.post("/topup-pin/new", requireUserAuth, requireCsrfIfCookie, (req, res) => {
  const now = new Date();
  const nowISO = now.toISOString();

  // تحقق لو فيه PIN نشط
  db.get(
    `SELECT id, pin, expires_at
     FROM topup_pins
     WHERE user_id = ? AND revoked = 0 AND expires_at > ?
     ORDER BY id DESC LIMIT 1`,
    [req.user.id, nowISO],
    (e1, active) => {
      if (e1) return res.status(500).json({ error: "DB error" });
      if (active) {
        return res.json({ pin: active.pin, expires_at: active.expires_at, existing: true });
      }

      const pin = String(Math.floor(100000 + Math.random() * 900000));
      const expires = new Date(now.getTime() + TOPUP_PIN_TTL_SEC * 1000).toISOString();

      db.run(
        `INSERT INTO topup_pins (user_id, pin, expires_at, created_at, revoked)
         VALUES (?, ?, ?, ?, 0)`,
        [req.user.id, pin, expires, nowISO],
        function (e2) {
          if (e2) return res.status(500).json({ error: "DB error" });
          return res.json({ pin, expires_at: expires });
        }
      );
    }
  );
});

// ====== Transactions & Transfers ======
app.get("/transactions", requireUserAuth, (req, res) => {
  db.all(
    `SELECT id, type, amount, balance_after, meta, created_at
     FROM transactions
     WHERE user_id = ?
     ORDER BY id DESC
     LIMIT 50`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ items: rows || [] });
    }
  );
});

app.post(
  "/transfer",
  requireUserAuth,
  requireCsrfIfCookie,
  body("to_phone").custom(isLibyanPhone).withMessage("رقم المستلم غير صحيح"),
  body("amount").isFloat({ gt: 0 }).withMessage("المبلغ غير صحيح"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const to_phone = String(req.body.to_phone).trim();
    const amt = Number(req.body.amount);

    db.get(`SELECT id, phone, balance FROM users WHERE id = ?`, [req.user.id], (e1, me) => {
      if (e1 || !me) return res.status(500).json({ error: "خطأ الخادم" });

      db.get(`SELECT id, phone, balance FROM users WHERE phone = ?`, [to_phone], (e2, dest) => {
        if (e2) return res.status(500).json({ error: "خطأ الخادم" });
        if (!dest) return res.status(404).json({ error: "المستلم غير موجود" });
        if (dest.id === me.id) return res.status(400).json({ error: "لا يمكنك التحويل لنفسك" });
        if (me.balance < amt) return res.status(400).json({ error: "الرصيد غير كافٍ" });

        db.serialize(() => {
          db.run("BEGIN");
          db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [amt, me.id]);
          db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [amt, dest.id]);

          db.get(`SELECT balance FROM users WHERE id = ?`, [me.id], (e3, m2) => {
            db.get(`SELECT balance FROM users WHERE id = ?`, [dest.id], (e4, d2) => {
              const now = new Date().toISOString();
              const metaOut = JSON.stringify({ to: dest.phone });
              const metaIn = JSON.stringify({ from: me.phone });

              db.run(
                `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
                 VALUES (?, 'transfer_out', ?, ?, ?, ?)`,
                [me.id, amt, m2?.balance ?? me.balance - amt, metaOut, now]
              );
              db.run(
                `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
                 VALUES (?, 'transfer_in', ?, ?, ?, ?)`,
                [dest.id, amt, d2?.balance ?? dest.balance + amt, metaIn, now]
              );

              db.run("COMMIT", (e5) => {
                if (e5) return res.status(500).json({ error: "فشل العملية" });
                return res.json({ ok: true });
              });
            });
          });
        });
      });
    });
  }
);

// Transfer by account number (user -> user)
app.post(
  "/transfer-account",
  requireUserAuth,
  requireCsrfIfCookie,
  body("account").isLength({ min: 4 }).withMessage("رقم حساب غير صحيح"),
  body("amount").isFloat({ gt: 0 }).withMessage("المبلغ غير صحيح"),
  body("save").optional({ values: 'falsy' }).isBoolean().toBoolean(),
  body("nickname").optional({ values: 'falsy' }).isLength({ max: 50 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const account = normalizeAccount(req.body.account);
    const amt = Number(req.body.amount);
    const wantSave = Boolean(req.body.save);
    const nickname = cleanStr(req.body.nickname || '');

    db.get(`SELECT id, phone, balance FROM users WHERE id=?`, [req.user.id], (eMe, me) => {
      if (eMe || !me) return res.status(500).json({ error: "خطأ الخادم" });

      db.get(
        `SELECT id, phone, full_name FROM users WHERE account_number = ?`,
        [account],
        (eDest, dest) => {
          if (eDest) return res.status(500).json({ error: "خطأ الخادم" });
          if (!dest) return res.status(404).json({ error: "الحساب غير موجود" });
          if (dest.id === me.id) return res.status(400).json({ error: "لا يمكنك التحويل لنفسك" });
          if (me.balance < amt) return res.status(400).json({ error: "الرصيد غير كافٍ" });

          db.serialize(() => {
            db.run("BEGIN");
            db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [amt, me.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [amt, dest.id]);

            db.get(`SELECT balance FROM users WHERE id = ?`, [me.id], (eB1, m2) => {
              db.get(`SELECT balance FROM users WHERE id = ?`, [dest.id], (eB2, d2) => {
                const now = new Date().toISOString();
                const metaOut = JSON.stringify({ to: account, via: "account" });
                const metaIn  = JSON.stringify({ from: me.phone, via: "account" });

                db.run(
                  `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
                   VALUES (?, 'transfer_out', ?, ?, ?, ?)`,
                  [me.id, amt, m2?.balance ?? (me.balance - amt), metaOut, now]
                );
                db.run(
                  `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
                   VALUES (?, 'transfer_in', ?, ?, ?, ?)`,
                  [dest.id, amt, d2?.balance ?? 0, metaIn, now]
                );

                const finish = () => {
                  db.run("COMMIT", (eC) => {
                    if (eC) return res.status(500).json({ error: "فشل العملية" });
                    return res.json({ ok: true });
                  });
                };

                if (!wantSave) return finish();

                const nick = nickname || maskName(dest.full_name);
                db.get(
                  `SELECT id FROM saved_recipients
                   WHERE owner_user_id = ? AND recipient_account = ? AND is_deleted = 0
                   LIMIT 1`,
                  [me.id, account],
                  (eS, ex) => {
                    if (eS) return finish();
                    if (ex) {
                      db.run(
                        `UPDATE saved_recipients
                         SET last_used_at=?, times_used=times_used+1, total_sent=total_sent+?
                         WHERE id=?`,
                        [now, amt, ex.id],
                        () => finish()
                      );
                    } else {
                      db.run(
                        `INSERT INTO saved_recipients
                         (owner_user_id, recipient_user_id, recipient_account, nickname, is_favorite, times_used, total_sent, is_deleted, created_at, last_used_at)
                         VALUES (?, ?, ?, ?, 0, 1, ?, 0, ?, ?)`,
                        [me.id, dest.id, account, nick, amt, now, now],
                        () => finish()
                      );
                    }
                  }
                );
              });
            });
          });
        }
      );
    });
  }
);

// ====== Services (Requests) ======
app.post(
  "/request",
  requireUserAuth,
  requireCsrfIfCookie,
  body("type").isIn(["topup","withdraw"]).withMessage("نوع الطلب غير صحيح"),
  body("amount").isFloat({ gt: 0 }).withMessage("المبلغ غير صحيح"),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    db.get(`SELECT allow_services FROM users WHERE id=?`, [req.user.id], (e,u)=>{
      if(e) return res.status(500).json({ error: "خطأ الخادم" });
      if(!u || Number(u.allow_services)!==1) return res.status(403).json({ error: "غير مخوّل لاستخدام الخدمات" });

      const { type } = req.body;
      const amount = Number(req.body.amount);
      const now = new Date().toISOString();

      db.run(
        `INSERT INTO requests (user_id, type, amount, status, created_at) VALUES (?, ?, ?, 'pending', ?)`,
        [req.user.id, type, amount, now],
        function (err) {
          if (err) return res.status(500).json({ error: "تعذّر إنشاء الطلب" });
          return res.json({ ok: true, id: this.lastID });
        }
      );
    });
  }
);

app.get("/my-requests", requireUserAuth, (req, res) => {
  db.all(
    `SELECT id, type, amount, status, note, created_at, resolved_at
     FROM requests WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ items: rows || [] });
    }
  );
});

// quick summary
app.get("/my-pending-total", requireUserAuth, (req, res) => {
  db.get(
    `SELECT COALESCE(SUM(amount),0) AS total FROM requests WHERE user_id = ? AND status = 'pending'`,
    [req.user.id],
    (e, row) => {
      if (e) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ total: Number(row?.total || 0) });
    }
  );
});

// List saved recipients
app.get("/recipients", requireUserAuth, (req, res) => {
  const q = cleanStr(req.query.q || "");
  const params = [req.user.id];
  let where = `WHERE sr.owner_user_id = ? AND sr.is_deleted = 0`;
  if (q) {
    where += ` AND (sr.nickname LIKE ? OR u.account_number LIKE ?)`;
    params.push(`%${q}%`, `%${q}%`);
  }
  db.all(
    `SELECT
       sr.id, sr.nickname, sr.recipient_account, sr.is_favorite,
       sr.times_used, sr.total_sent, sr.created_at, sr.last_used_at,
       u.full_name, u.phone
     FROM saved_recipients sr
     LEFT JOIN users u ON u.id = sr.recipient_user_id
     ${where}
     ORDER BY sr.is_favorite DESC, COALESCE(sr.last_used_at, sr.created_at) DESC
     LIMIT 100`,
    params,
    (e, rows) => {
      if (e) return res.status(500).json({ error: "خطأ الخادم" });
      const items = (rows || []).map(r => ({
        id: r.id,
        nickname: r.nickname || maskName(r.full_name),
        account: r.recipient_account,
        favorite: Number(r.is_favorite) === 1,
        times_used: r.times_used,
        total_sent: Number(r.total_sent || 0),
        display_name: maskName(r.full_name),
        phone_hint: phoneLast2(r.phone)
      }));
      res.json({ items });
    }
  );
});

// ====== Admin auth (session) ======

// ربط هذا الجهاز للأدمن
app.post("/admin/bind-device", (req, res) => {
  if (!ADMIN_BIND_KEY || !ADMIN_DEVICE_SECRET) {
    return res.status(400).json({ error: "Device binding not configured" });
  }
  const key = String(req.headers["x-bind-key"] || req.body?.key || "");
  if (!key || key !== ADMIN_BIND_KEY) {
    return res.status(403).json({ error: "Invalid bind key" });
  }
  const sig = signDevice(req.headers["user-agent"] || "");
  if (!sig) return res.status(500).json({ error: "Device secret missing" });
  setCookie(res, "admin_device", sig, { maxAge: 365 * 24 * 60 * 60 * 1000 });
  return res.json({ ok: true });
});

// دخول الأدمن
app.post(
  "/admin/login",
  authLimiter,
  body("username").trim().isLength({ min: 2 }).withMessage("اسم دخول غير صالح"),
  body("password").isLength({ min: 1 }).withMessage("أدخل كلمة المرور"),
  async (req, res) => {
    if (!ipAllowed(req)) return res.status(403).json({ error: "IP not allowed" });

    if (ADMIN_DEVICE_ENFORCE) {
      const dev = getCookie(req, "admin_device");
      const must = signDevice(req.headers["user-agent"] || "");
      if (!dev || !must || dev !== must) {
        return res.status(403).json({ error: "هذا الجهاز غير مربوط للأدمن" });
      }
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "بيانات غير صحيحة" });

    const { username, password } = matchedData(req, { locations: ["body"] });

    const key = `A:${username}`;
    if (checkLock(key)) return res.status(429).json({ error: "محاولات كثيرة. جرّب لاحقًا." });

    db.get(`SELECT id, username, password_hash, role, is_active FROM admins WHERE username = ?`, [username], async (e, row) => {
      if (e) return res.status(500).json({ error: "DB error" });
      if (!row || Number(row.is_active) !== 1) { recordFail(key); return res.status(401).json({ error: "بيانات غير صحيحة" }); }

      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) { recordFail(key); return res.status(401).json({ error: "بيانات غير صحيحة" }); }

      recordSuccess(key);

      const token = signAdminToken({ typ: "admin", aid: row.id, role: row.role });
      setCookie(res, "floosy_admin", token, { maxAge: 2 * 24 * 60 * 60 * 1000 });

      const csrf = crypto.randomBytes(16).toString("hex");
      setReadableCookie(res, "admin_csrf", csrf, { maxAge: 2 * 24 * 60 * 60 * 1000 });

      res.json({ ok: true });
    });
  }
);

// خروج الأدمن
app.post("/admin/logout", requireAdmin, (req, res) => {
  setCookie(res, "floosy_admin", "", { maxAge: 0 });
  setReadableCookie(res, "admin_csrf", "", { maxAge: 0 });
  res.json({ ok: true });
});

// حالة جلسة الأدمن + csrf
app.get("/admin/session", requireAdmin, (req, res) => {
  const csrf = getCookie(req, "admin_csrf") || "";
  res.json({ admin: req.admin, csrf });
});

// ====== Admin APIs ======
app.post(
  "/admin/create-user",
  requireAdmin,
  requireCsrfIfCookie,
  body("full_name").trim().isLength({ min: 2 }).withMessage("اسم قصير"),
  body("phone").custom(isLibyanPhone).withMessage("هاتف غير صحيح"),
  body("email").optional({ values: "falsy" }).custom(isValidEmail).withMessage("بريد غير صالح"),
  body("password").custom(isStrongPassword).withMessage("كلمة مرور ضعيفة"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const { full_name, phone, email, password } = matchedData(req, { locations: ["body"] });
    const hash = await bcrypt.hash(password, 10);
    const created_at = new Date().toISOString();

    db.run(
      `INSERT INTO users (full_name, phone, email, password, password_hash, balance, created_at, email_verified, is_active, allow_services)
       VALUES (?, ?, ?, '', ?, 0, ?, 0, 1, 1)`,
      [cleanStr(full_name), phone.trim(), (email||"").toLowerCase(), hash, created_at],
      function (err) {
        if (err) {
          if (String(err).includes("UNIQUE")) {
            const field = String(err).includes("phone") ? "رقم الهاتف" : "البريد";
            return res.status(409).json({ error: `${field} مستخدم من قبل` });
          }
          return res.status(500).json({ error: "DB error" });
        }
        res.json({ ok: true, id: this.lastID });
      }
    );
  }
);

app.get("/admin/users-count", requireAdmin, (_req, res) => {
  db.get(`SELECT COUNT(*) AS cnt FROM users`, (err, row) => {
    if (err) return res.status(500).json({ error: "خطأ الخادم" });
    res.json({ count: row?.cnt ?? 0 });
  });
});

app.get("/admin/users", requireAdmin, (req, res) => {
  const isActive = req.query.is_active;
  const verified = req.query.verified;
  const conds = [];
  const params = [];
  if (isActive === "0" || isActive === "1") { conds.push("is_active = ?"); params.push(Number(isActive)); }
  if (verified === "0" || verified === "1") { conds.push("email_verified = ?"); params.push(Number(verified)); }

  const where = conds.length ? `WHERE ${conds.join(" AND ")} ` : "";
  db.all(
    `SELECT id, full_name, phone, email, balance, created_at, email_verified, is_active
     FROM users ${where} ORDER BY id DESC`,
    params,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json(rows || []);
    }
  );
});

app.get("/admin/search-user", requireAdmin, (req, res) => {
  const q = cleanStr(req.query.q || "");
  const isActive = req.query.is_active;
  const verified = req.query.verified;

  const conds = [];
  const params = [];
  if (q) {
    conds.push("(full_name LIKE ? OR phone LIKE ? OR email LIKE ?)");
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (isActive === "0" || isActive === "1") { conds.push("is_active = ?"); params.push(Number(isActive)); }
  if (verified === "0" || verified === "1") { conds.push("email_verified = ?"); params.push(Number(verified)); }

  const where = conds.length ? `WHERE ${conds.join(" AND ")} ` : "";
  db.all(
    `SELECT id, full_name, phone, email, balance, created_at, email_verified, is_active
     FROM users ${where} ORDER BY id DESC LIMIT 50`,
    params,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ users: rows || [] });
    }
  );
});

app.post("/admin/update-balance", requireAdmin, requireCsrfIfCookie, (req, res) => {
  const phone = cleanStr(req.body?.phone || "");
  const a = Number(req.body?.amount);
  if (!phone || !Number.isFinite(a)) return res.status(400).json({ error: "الهاتف أو المبلغ غير صحيح" });

  db.get(`SELECT id, balance FROM users WHERE phone = ?`, [phone], (e0, u) => {
    if (e0) return res.status(500).json({ error: "خطأ الخادم" });
    if (!u) return res.status(404).json({ error: "المستخدم غير موجود" });

    db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [a, u.id], function (err) {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });

      db.get(`SELECT id, full_name, phone, email, balance, created_at, email_verified, is_active FROM users WHERE id = ?`, [u.id], (e2, row) => {
        if (e2 || !row) return res.status(500).json({ error: "حدث خطأ بعد التحديث" });

        const now = new Date().toISOString();
        const meta = JSON.stringify({ by: "admin" });
        db.run(
          `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
           VALUES (?, 'admin_adj', ?, ?, ?, ?)`,
          [u.id, Math.abs(a), row.balance, meta, now]
        );

        res.json({ user: row });
      });
    });
  });
});

app.post("/admin/set-active", requireAdmin, requireCsrfIfCookie, (req, res) => {
  const uid = Number(req.body?.user_id);
  const isActive = Number(req.body?.is_active);
  if (!Number.isFinite(uid) || (isActive !== 0 && isActive !== 1)) {
    return res.status(400).json({ error: "بيانات غير صحيحة" });
  }
  db.run(`UPDATE users SET is_active = ? WHERE id = ?`, [isActive, uid], function (err) {
    if (err) return res.status(500).json({ error: "خطأ الخادم" });
    db.get(`SELECT id, full_name, phone, email, balance, created_at, email_verified, is_active FROM users WHERE id = ?`, [uid], (e2, row) => {
      if (e2 || !row) return res.status(500).json({ error: "تعذر جلب المستخدم" });
      res.json({ user: row });
    });
  });
});

app.get("/admin/user/:id/transactions", requireAdmin, (req, res) => {
  const uid = Number(req.params.id);
  if (!Number.isFinite(uid)) return res.status(400).json({ error: "معرّف غير صحيح" });
  db.all(
    `SELECT id, type, amount, balance_after, meta, created_at
     FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 100`,
    [uid],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ items: rows || [] });
    }
  );
});

app.get("/admin/requests", requireAdmin, (req, res) => {
  const status = cleanStr(req.query.status || "pending");
  const type = cleanStr(req.query.type || "");
  const conds = [];
  const params = [];
  if (status) { conds.push("r.status = ?"); params.push(status); }
  if (type === "topup" || type === "withdraw") { conds.push("r.type = ?"); params.push(type); }
  const where = conds.length ? `WHERE ${conds.join(" AND ")} ` : "";

  db.all(
    `SELECT r.id, r.type, r.amount, r.status, r.note, r.created_at, r.resolved_at,
            u.id AS user_id, u.full_name, u.phone
     FROM requests r
     JOIN users u ON u.id = r.user_id
     ${where}
     ORDER BY r.id DESC
     LIMIT 200`,
    params,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "خطأ الخادم" });
      res.json({ items: rows || [] });
    }
  );
});

const DAILY_TOPUP_LIMIT = 1000;

app.post("/admin/requests/:id/approve", requireAdmin, requireCsrfIfCookie, (req, res) => {
  const id = Number(req.params.id);
  const note = cleanStr(req.body?.note || "");
  if (!Number.isFinite(id)) return res.status(400).json({ error: "رقم طلب غير صحيح" });

  db.get(`SELECT * FROM requests WHERE id = ?`, [id], (e1, r) => {
    if (e1) return res.status(500).json({ error: "خطأ الخادم" });
    if (!r) return res.status(404).json({ error: "الطلب غير موجود" });
    if (r.status !== "pending") return res.status(400).json({ error: "الطلب غير معلق" });

    db.get(`SELECT id, balance, phone FROM users WHERE id = ?`, [r.user_id], (e2, u) => {
      if (e2 || !u) return res.status(500).json({ error: "المستخدم غير موجود" });

      const now = new Date().toISOString();
      const amt = Number(r.amount);

      const finish = () => {
        db.serialize(() => {
          db.run("BEGIN");
          if (r.type === "topup") {
            db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [amt, u.id]);
          } else if (r.type === "withdraw") {
            if (u.balance < amt) {
              db.run("ROLLBACK");
              return res.status(400).json({ error: "الرصيد غير كافٍ للسحب" });
            }
            db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [amt, u.id]);
          }

          db.get(`SELECT balance FROM users WHERE id = ?`, [u.id], (e3, balRow) => {
            if (e3 || !balRow) { db.run("ROLLBACK"); return res.status(500).json({ error: "فشل تحديث الرصيد" }); }

            const tType = r.type === "topup" ? "topup" : "withdraw";
            const meta = JSON.stringify({ by: "admin", request_id: r.id });
            db.run(
              `INSERT INTO transactions (user_id, type, amount, balance_after, meta, created_at)
               VALUES (?, ?, ?, ?, ?, ?)`,
              [u.id, tType, amt, balRow.balance, meta, now]
            );

            db.run(
              `UPDATE requests SET status='approved', note=?, resolved_at=? WHERE id = ?`,
              [note, now, id],
              (e4) => {
                if (e4) { db.run("ROLLBACK"); return res.status(500).json({ error: "فشل ختم الطلب" }); }
                db.run("COMMIT", (e5) => {
                  if (e5) return res.status(500).json({ error: "فشل العملية" });
                  return res.json({ ok: true });
                });
              }
            );
          });
        });
      };

      if (r.type !== "topup") return finish();

      const start = new Date();
      start.setHours(0, 0, 0, 0);
      const startISO = start.toISOString();

      db.get(
        `SELECT COALESCE(SUM(amount),0) AS s
         FROM transactions
         WHERE user_id=? AND type='topup' AND created_at >= ?`,
        [u.id, startISO],
        (eSum, rowSum) => {
          if (eSum) return res.status(500).json({ error: "فشل حساب حد اليوم" });
          const sum = Number(rowSum?.s || 0);
          if (sum + amt > DAILY_TOPUP_LIMIT) {
            return res.status(400).json({ error: `تجاوز حد التعبئة اليومي (${DAILY_TOPUP_LIMIT} LYD)` });
          }
          finish();
        }
      );
    });
  });
});

app.post("/admin/requests/:id/reject", requireAdmin, requireCsrfIfCookie, (req, res) => {
  const id = Number(req.params.id);
  const note = cleanStr(req.body?.note || "");
  if (!Number.isFinite(id)) return res.status(400).json({ error: "رقم طلب غير صحيح" });

  db.get(`SELECT status FROM requests WHERE id = ?`, [id], (e1, r) => {
    if (e1) return res.status(500).json({ error: "خطأ الخادم" });
    if (!r) return res.status(404).json({ error: "الطلب غير موجود" });
    if (r.status !== "pending") return res.status(400).json({ error: "الطلب غير معلق" });

    const now = new Date().toISOString();
    db.run(
      `UPDATE requests SET status='rejected', note=?, resolved_at=? WHERE id = ?`,
      [note, now, id],
      (e2) => {
        if (e2) return res.status(500).json({ error: "تعذّر الرفض" });
        res.json({ ok: true });
      }
    );
  });
});

// ====== Contact form ======
app.post(
  "/contact",
  body("name").trim().isLength({ min: 2 }).withMessage("أدخل اسم صحيح"),
  body("email").custom(isValidEmail).withMessage("أدخل بريد صحيح"),
  body("message").trim().isLength({ min: 5 }).withMessage("الرسالة قصيرة"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
      return res.status(500).json({ error: "بريد الإرسال غير مُعد" });
    }
    const { name, email, message } = matchedData(req, { locations: ['body'] });
    try {
      await transporter.sendMail({
        from: `Floosy Contact <${MAIL_FROM}>`,
        to: ADMIN_EMAIL,
        subject: `رسالة جديدة من ${name}`,
        text: `From: ${name} <${email}>\n\n${message}`,
      });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: "تعذّر إرسال الرسالة" });
    }
  }
);

// ====== Start ======
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
