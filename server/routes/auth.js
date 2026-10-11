import express from 'express';
import { q } from '../db.js';
import {
  hashPassword, verifyPassword, generateTotpSecret, verifyTotp,
  signJwt, newJti
} from '../auth.js';
import { requireAuth } from '../middleware.js';

export const authRouter = express.Router();

const JWT_SECRET = process.env.SESSION_SECRET;
const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;

// POST /api/auth/login
authRouter.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
    const normalizedEmail = String(email).trim().toLowerCase();

    // Rate check
    const since = Date.now() - 15 * 60 * 1000;
    const failCount = await q(
      `SELECT COUNT(*) c FROM login_attempts
       WHERE (email = $1 OR ip = $2) AND success = FALSE AND created_at > $3`,
      [normalizedEmail, req.ip, since]
    );
    if (Number(failCount.rows[0].c) >= 20) {
      return res.status(429).json({ error: 'too_many_requests' });
    }

    const user = (await q('SELECT * FROM users WHERE email = $1', [normalizedEmail])).rows[0];

    if (!user) {
      verifyPassword(password, '$2a$12$' + 'a'.repeat(53));
      await q('INSERT INTO login_attempts (email, ip, success, created_at) VALUES ($1,$2,FALSE,$3)',
        [normalizedEmail, req.ip, Date.now()]);
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    if (user.locked_until > Date.now()) {
      return res.status(423).json({
        error: 'locked',
        retry_after: Math.ceil((user.locked_until - Date.now()) / 1000)
      });
    }

    if (!verifyPassword(password, user.password_hash)) {
      const attempts = user.failed_attempts + 1;
      const lock = attempts >= MAX_FAILED ? Date.now() + LOCK_MS : 0;
      await q('UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3',
        [attempts, lock, user.id]);
      await q('INSERT INTO login_attempts (email, ip, success, created_at) VALUES ($1,$2,FALSE,$3)',
        [normalizedEmail, req.ip, Date.now()]);
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    await q('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = $1', [user.id]);
    await q('INSERT INTO login_attempts (email, ip, success, created_at) VALUES ($1,$2,TRUE,$3)',
      [normalizedEmail, req.ip, Date.now()]);

    if (user.totp_enabled) {
      // Short-lived pending token
      const pendingToken = signJwt(
        { sub: user.id, stage: 'pending_totp' },
        JWT_SECRET,
        { expiresIn: '5m' }
      );
      res.cookie('pending', pendingToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 5 * 60 * 1000,
        path: '/'
      });
      return res.json({ stage: 'totp' });
    }

    await issueToken(res, user);
    res.json({
      stage: 'authenticated',
      user: { email: user.email, name: user.name, role: user.role }
    });
  } catch (err) { next(err); }
});

// POST /api/auth/totp
authRouter.post('/totp', async (req, res, next) => {
  try {
    const pending = req.cookies?.pending;
    if (!pending) return res.status(400).json({ error: 'no_pending_login' });
    const claims = verifyJwt(pending, JWT_SECRET);
    if (!claims || claims.stage !== 'pending_totp') {
      res.clearCookie('pending');
      return res.status(400).json({ error: 'no_pending_login' });
    }
    const { code } = req.body || {};
    const user = (await q('SELECT * FROM users WHERE id = $1', [claims.sub])).rows[0];
    if (!user || !verifyTotp(user.totp_secret, code)) {
      res.clearCookie('pending');
      return res.status(401).json({ error: 'invalid_totp' });
    }
    res.clearCookie('pending');
    await issueToken(res, user);
    res.json({
      stage: 'authenticated',
      user: { email: user.email, name: user.name, role: user.role }
    });
  } catch (err) { next(err); }
});

// POST /api/auth/logout
authRouter.post('/logout', requireAuth, async (req, res, next) => {
  try {
    const token = req.cookies?.auth;
    const claims = verifyJwt(token, JWT_SECRET);
    if (claims) {
      await q(
        `INSERT INTO revoked_tokens (jti, user_id, expires_at, revoked_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING`,
        [claims.jti, claims.sub, claims.exp * 1000, Date.now()]
      );
    }
    res.clearCookie('auth', { path: '/' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// GET /api/auth/me
authRouter.get('/me', requireAuth, (req, res) => {
  res.json({ user: { email: req.user.email, name: req.user.name, role: req.user.role } });
});

async function issueToken(res, user) {
  const jti = newJti();
  const token = signJwt(
    { sub: user.id, email: user.email, name: user.name, role: user.role, jti },
    JWT_SECRET
  );
  res.cookie('auth', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000,
    path: '/'
  });
}
