const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const router = express.Router();

const CODE_TTL_MINUTES = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'me-plus-dev-secret-change-in-production';

// ---- PBKDF2 password hashing (pure Node crypto, no native deps) ----
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return `${salt.toString('base64')}:${hash.toString('base64')}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltB64, hashB64] = stored.split(':');
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  const actual = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

// POST /api/auth/signup
router.post('/signup', async (req, res) => {
  try {
    const { email, lastName, firstName, password, agreeTerms } = req.body || {};

    if (!email || !lastName || !firstName || !password) {
      return res.status(400).json({ error: 'MISSING_FIELDS', message: '필수 항목이 비어 있습니다.' });
    }
    if (!agreeTerms) {
      return res.status(400).json({ error: 'TERMS_NOT_AGREED', message: '약관에 동의해야 합니다.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: '비밀번호는 8자 이상이어야 합니다.' });
    }

    const existing = await db.getByEmail(email);
    if (existing && existing.emailVerified) {
      return res.status(409).json({ error: 'EMAIL_TAKEN', message: '이미 가입된 이메일입니다.' });
    }

    const passwordHash = hashPassword(password);
    const code = generateCode();
    const codeHash = hashPassword(code);
    const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000).toISOString();

    await db.upsertPending({
      email, lastName, firstName, passwordHash,
      verificationCodeHash: codeHash,
      verificationExpiresAt: expiresAt,
    });

    // TODO: 실제 SMTP 연동 전까지는 이메일 발송 대신 서버 로그로만 확인 (개발용)
    console.log(`[DEV] ${email} 인증코드: ${code} (만료 ${CODE_TTL_MINUTES}분)`);

    return res.json({ email, message: '인증 코드를 발송했습니다.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// POST /api/auth/verify
router.post('/verify', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'MISSING_FIELDS' });

    const user = await db.getByEmail(email);
    if (!user) return res.status(404).json({ error: 'NOT_FOUND', message: '가입 정보를 찾을 수 없습니다.' });
    if (user.emailVerified) return res.status(409).json({ error: 'ALREADY_VERIFIED' });
    if (!user.verificationExpiresAt || new Date(user.verificationExpiresAt) < new Date()) {
      return res.status(400).json({ error: 'CODE_EXPIRED', message: '인증 코드가 만료되었습니다. 다시 요청해주세요.' });
    }

    const codeOk = verifyPassword(String(code), user.verificationCodeHash || '');
    if (!codeOk) return res.status(400).json({ error: 'CODE_INVALID', message: '인증 코드가 일치하지 않습니다.' });

    const updated = await db.markVerified(email);
    const token = signToken(updated);
    return res.json({ token, user: { email: updated.email, firstName: updated.firstName, lastName: updated.lastName } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// POST /api/auth/verify/resend
router.post('/verify/resend', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'MISSING_FIELDS' });

    const user = await db.getByEmail(email);
    if (!user) return res.status(404).json({ error: 'NOT_FOUND' });
    if (user.emailVerified) return res.status(409).json({ error: 'ALREADY_VERIFIED' });

    const code = generateCode();
    const codeHash = hashPassword(code);
    const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000).toISOString();
    await db.updateCode(email, codeHash, expiresAt);

    console.log(`[DEV] ${email} 재발송 인증코드: ${code} (만료 ${CODE_TTL_MINUTES}분)`);

    return res.json({ email, message: '인증 코드를 다시 보냈습니다.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });

    const user = await db.getByEmail(email);
    if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

    const ok = verifyPassword(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

    if (!user.emailVerified) return res.status(403).json({ error: 'EMAIL_NOT_VERIFIED', message: '이메일 인증을 먼저 완료해주세요.' });

    const token = signToken(user);
    return res.json({ token, user: { email: user.email, firstName: user.firstName, lastName: user.lastName } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// GET /api/auth/me
router.get('/me', async (req, res) => {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'NO_TOKEN' });

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await db.getByEmail(payload.email);
    if (!user) return res.status(404).json({ error: 'NOT_FOUND' });

    return res.json({ user: { email: user.email, firstName: user.firstName, lastName: user.lastName, emailVerified: user.emailVerified } });
  } catch (err) {
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
});

module.exports = router;
