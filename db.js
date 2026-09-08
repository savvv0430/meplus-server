// PostgreSQL-backed storage (Render Postgres). Data persists centrally,
// reachable from anywhere with internet access — not tied to one PC.
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL 환경변수가 설정되지 않았어요. Render 대시보드 > 이 서비스 > Environment 에서 설정해주세요.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

async function init() {
  const sql = fs.readFileSync(path.join(__dirname, 'init.sql'), 'utf8');
  await pool.query(sql);
  console.log('DB 마이그레이션 완료 (users 테이블 준비됨)');
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    lastName: row.last_name,
    firstName: row.first_name,
    passwordHash: row.password_hash,
    emailVerified: row.email_verified,
    verificationCodeHash: row.verification_code_hash,
    verificationExpiresAt: row.verification_expires_at,
    createdAt: row.created_at,
  };
}

async function getByEmail(email) {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rowToUser(rows[0]);
}

async function upsertPending(user) {
  const { email, lastName, firstName, passwordHash, verificationCodeHash, verificationExpiresAt } = user;
  await pool.query(
    `INSERT INTO users (email, last_name, first_name, password_hash, verification_code_hash, verification_expires_at, email_verified)
     VALUES ($1, $2, $3, $4, $5, $6, FALSE)
     ON CONFLICT (email) DO UPDATE SET
       last_name = EXCLUDED.last_name,
       first_name = EXCLUDED.first_name,
       password_hash = EXCLUDED.password_hash,
       verification_code_hash = EXCLUDED.verification_code_hash,
       verification_expires_at = EXCLUDED.verification_expires_at`,
    [email, lastName, firstName, passwordHash, verificationCodeHash, verificationExpiresAt]
  );
  return getByEmail(email);
}

async function updateCode(email, verificationCodeHash, verificationExpiresAt) {
  await pool.query(
    'UPDATE users SET verification_code_hash = $2, verification_expires_at = $3 WHERE email = $1',
    [email, verificationCodeHash, verificationExpiresAt]
  );
  return getByEmail(email);
}

async function markVerified(email) {
  await pool.query(
    `UPDATE users SET email_verified = TRUE, verification_code_hash = NULL, verification_expires_at = NULL WHERE email = $1`,
    [email]
  );
  return getByEmail(email);
}

module.exports = { init, getByEmail, upsertPending, updateCode, markVerified };
