-- Auth
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','editor','viewer')),
  totp_secret TEXT,
  totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  last_login BIGINT
);

-- Revoked JWTs (for logout — serverless has no session store)
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL,
  revoked_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_tokens(expires_at);

-- Executive committee
CREATE TABLE IF NOT EXISTS executives (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  position_order INTEGER NOT NULL DEFAULT 100,
  bio TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  linkedin TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  photo_blob_key TEXT NOT NULL DEFAULT '',
  photo_thumb_key TEXT NOT NULL DEFAULT '',
  term TEXT NOT NULL DEFAULT '',
  is_current BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft','published','archived')),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exec_order ON executives(is_current DESC, position_order ASC);

-- Media library (photos + video metadata; video files live on YouTube)
CREATE TABLE IF NOT EXISTS media (
  id SERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('photo','video')),
  title TEXT NOT NULL,
  caption TEXT NOT NULL DEFAULT '',
  event_id INTEGER,
  album TEXT NOT NULL DEFAULT 'General',
  blob_key TEXT NOT NULL DEFAULT '',        -- for photos
  thumb_blob_key TEXT NOT NULL DEFAULT '',
  youtube_id TEXT NOT NULL DEFAULT '',      -- for videos
  mime TEXT NOT NULL DEFAULT '',
  width INTEGER NOT NULL DEFAULT 0,
  height INTEGER NOT NULL DEFAULT 0,
  duration_seconds INTEGER NOT NULL DEFAULT 0,
  file_size INTEGER NOT NULL DEFAULT 0,
  taken_at TEXT,
  uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft','published','archived')),
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_kind ON media(kind, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_album ON media(album);

-- Events
CREATE TABLE IF NOT EXISTS events (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'Other',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  capacity INTEGER NOT NULL DEFAULT 0,
  registered INTEGER NOT NULL DEFAULT 0,
  cover_media_id INTEGER REFERENCES media(id) ON DELETE SET NULL,
  description TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_status_date ON events(status, date DESC);

-- Programs
CREATE TABLE IF NOT EXISTS programs (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  cover_media_id INTEGER REFERENCES media(id) ON DELETE SET NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft','published','archived')),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

-- News
CREATE TABLE IF NOT EXISTS news (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  excerpt TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  author TEXT NOT NULL DEFAULT '',
  cover_media_id INTEGER REFERENCES media(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  published_at TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

-- Settings
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at BIGINT NOT NULL
);

-- Activity log
CREATE TABLE IF NOT EXISTS activity_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at DESC);

-- Login attempts (brute-force protection)
CREATE TABLE IF NOT EXISTS login_attempts (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  ip TEXT NOT NULL,
  success BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_email_time ON login_attempts(email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_ip_time ON login_attempts(ip, created_at DESC);
