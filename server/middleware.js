import { q } from './db.js';
import { verifyJwt, signCsrf, constantTimeEqual } from './auth.js';

const JWT_SECRET = process.env.SESSION_SECRET;

// ---------- Auth via HttpOnly cookie containing JWT ----------
export async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.auth;
    if (!token || typeof token !== 'string') {
      return res.status(401).json({ error: 'unauthenticated' });
    }

    const claims = verifyJwt(token, JWT_SECRET);
    if (!claims) {
      res.clearCookie('auth');
      return res.status(401).json({ error: 'invalid_token' });
    }

    // Check revocation
    const revoked = await q('SELECT 1 FROM revoked_tokens WHERE jti = $1', [claims.jti]);
    if (revoked.rowCount > 0) {
      res.clearCookie('auth');
      return res.status(401).json({ error: 'token_revoked' });
    }

    req.user = {
      id: claims.sub,
      email: claims.email,
      role: claims.role,
      name: claims.name,
      jti: claims.jti,
      csrfSecret: process.env.CSRF_SECRET || JWT_SECRET
    };
    next();
  } catch (err) {
    next(err);
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// ---------- CSRF: HMAC of JWT jti ----------
export function csrfIssuer(req, res, next) {
  if (req.user) {
    res.locals.csrfToken = signCsrf(req.user.jti, req.user.csrfSecret);
  }
  next();
}

export function csrfProtect(req, res, next) {
  if (!req.user) return next();
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const provided = req.headers['x-csrf-token'];
  const expected = signCsrf(req.user.jti, req.user.csrfSecret);
  if (!provided || !constantTimeEqual(provided, expected)) {
    return res.status(403).json({ error: 'csrf_invalid' });
  }
  next();
}

export function noStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store, private');
  next();
}

export async function auditLog(action) {
  return (req, res, next) => {
    res.on('finish', async () => {
      if (res.statusCode < 400 && req.user) {
        try {
          await q(
            `INSERT INTO activity_log (user_id, action, detail, ip, created_at)
             VALUES ($1, $2, $3, $4, $5)`,
            [req.user.id, action,
             req.params?.id ? `id=${req.params.id}` : '',
             req.ip || '', Date.now()]
          );
        } catch (err) { console.error('[audit]', err.message); }
      }
    });
    next();
  };
}

export function errorHandler(err, req, res, _next) {
  console.error('[error]', err.message);
  if (res.headersSent) return;
  const status = err.status || 500;
  res.status(status).json({ error: err.code || 'internal_error' });
}
