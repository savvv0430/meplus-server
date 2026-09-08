-- Me+ 계정 테이블
CREATE TABLE IF NOT EXISTS users (
  id                     SERIAL PRIMARY KEY,
  email                  TEXT UNIQUE NOT NULL,
  last_name              TEXT NOT NULL,
  first_name             TEXT NOT NULL,
  password_hash          TEXT NOT NULL,
  email_verified         BOOLEAN NOT NULL DEFAULT FALSE,
  verification_code_hash TEXT,
  verification_expires_at TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
