import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import crypto from 'node:crypto';

const BCRYPT_COST = 12;
const JWT_TTL = '30m';

export function hashPassword(p) { return bcrypt.hashSync(p, BCRYPT_COST); }
export function verifyPassword(p, h) {
  if (typeof h !== 'string' || !h.startsWith('$2')) {
    bcrypt.compareSync(p, '$2a$12$' + 'a'.repeat(53));
    return false;
  }
  return bcrypt.compareSync(p, h);
}

export function generateTotpSecret(email) {
  return speakeasy.generateSecret({
    name: `IEEE DIU WIE (${email})`,
    issuer: 'IEEE DIU WIE Admin',
    length: 32
  });
}

export function verifyTotp(secret, token) {
  if (!secret || !/^\d{6}$/.test(String(token))) return false;
  return speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
}

export function signJwt(payload, secret, opts = {}) {
  return jwt.sign(payload, secret, {
    expiresIn: JWT_TTL,
    issuer: 'ieee-diu-wie',
    audience: 'admin',
    ...opts
  });
}

export function verifyJwt(token, secret) {
  try {
    return jwt.verify(token, secret, {
      issuer: 'ieee-diu-wie',
      audience: 'admin'
    });
  } catch {
    return null;
  }
}

export function newJti() {
  return crypto.randomBytes(16).toString('hex');
}

export function signCsrf(jti, secret) {
  const h = crypto.createHmac('sha256', secret);
  h.update(jti);
  return h.digest('base64url');
}

export function constantTimeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
