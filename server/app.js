import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';

import { authRouter } from './routes/auth.js';
import { publicRouter } from './routes/public.js';
import { executivesRouter } from './routes/executives.js';
import { mediaRouter } from './routes/media.js';
import { settingsRouter } from './routes/settings.js';
import { readBlob } from './blobs.js';
import { errorHandler, requireAuth, csrfIssuer } from './middleware.js';

export const app = express();

app.set('trust proxy', 1); // Netlify sits in front

// ---------- Security headers ----------
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://i.ytimg.com', 'https://img.youtube.com'],
      mediaSrc: ["'self'", 'blob:'],
      frameSrc: ['https://www.youtube.com', 'https://www.youtube-nocookie.com'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'cross-origin' }, // allow blob playback
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard: { action: 'deny' },
  noSniff: true
}));

// ---------- Body parsing ----------
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser());

// ---------- CORS (same-origin only in prod) ----------
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && new URL(origin).hostname.endsWith('.netlify.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- Global rate limit ----------
app.use('/api', rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  // IMPORTANT: in-memory store is per-Lambda — good enough for a small branch
  // For real rate limiting, swap for @upstash/ratelimit (Redis)
  message: { error: 'too_many_requests' }
}));

// ---------- CSRF token issuance ----------
app.use('/api', csrfIssuer);

// ---------- Routes ----------
app.use('/api/auth', authRouter);
app.use('/api/public', publicRouter);
app.use('/api/executives', executivesRouter);
app.use('/api/media', mediaRouter);
app.use('/api/settings', settingsRouter);

app.get('/api/csrf', requireAuth, (req, res) => {
  res.json({ token: res.locals.csrfToken });
});

app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
// Add to server/app.js, after route imports


app.get('/api/blob/*', async (req, res, next) => {
  try {
    const key = req.params[0]; // everything after /api/blob/
    // Path safety
    if (!key || key.includes('..')) return res.status(400).end();
    const blob = await readBlob(key);
    if (!blob) return res.status(404).end();

    res.setHeader('Content-Type', blob.contentType);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(blob.buffer);
  } catch (err) { next(err); }
});
// ---------- Error handling ----------
app.use(errorHandler);

export default app;
