import { getStore } from '@netlify/blobs';
import sharp from 'sharp';
import crypto from 'node:crypto';
import { fileTypeFromBuffer } from 'file-type';

const IMAGE_MIMES = new Set(['image/jpeg','image/png','image/webp','image/avif','image/gif']);

function store() {
  // Netlify Blobs — getStore picks up site ID + token from env automatically
  return getStore('ieee-wie-media');
}

// ---------- Upload an image ----------
export async function uploadImage(buffer, subdir = 'photos', opts = {}) {
  const maxWidth = opts.maxWidth || 2000;
  const thumbSize = opts.thumbSize || 480;

  // 1. Magic-byte validation
  const detected = await fileTypeFromBuffer(buffer);
  if (!detected || !IMAGE_MIMES.has(detected.mime)) {
    const e = new Error('invalid_image_content');
    e.code = 'invalid_image_content';
    e.status = 415;
    throw e;
  }

  // 2. Full-size
  const { data, info } = await sharp(buffer, { failOn: 'error', limitInputPixels: 80_000_000 })
    .rotate()
    .resize({ width: maxWidth, withoutEnlargement: true, fit: 'inside' })
    .webp({ quality: 85, effort: 5 })
    .toBuffer({ resolveWithObject: true });

  // 3. Thumbnail
  const thumb = await sharp(buffer, { failOn: 'error' })
    .rotate()
    .resize({ width: thumbSize, height: thumbSize, fit: 'cover', position: 'attention' })
    .webp({ quality: 80, effort: 5 })
    .toBuffer();

  // 4. Persist under random keys
  const base = crypto.randomBytes(16).toString('hex');
  const fullKey = `${subdir}/${base}.webp`;
  const thumbKey = `${subdir}/${base}-thumb.webp`;

  const s = store();
  await s.set(fullKey, data, {
    metadata: { contentType: 'image/webp', size: String(data.length) }
  });
  await s.set(thumbKey, thumb, {
    metadata: { contentType: 'image/webp', size: String(thumb.length) }
  });

  return {
    blobKey: fullKey,
    thumbKey,
    width: info.width,
    height: info.height,
    size: data.length
  };
}

// ---------- Read a blob ----------
export async function readBlob(key) {
  const s = store();
  const result = await s.getWithMetadata(key, { type: 'arrayBuffer' });
  if (!result || !result.data) return null;
  return {
    buffer: Buffer.from(result.data),
    contentType: result.metadata?.contentType || 'application/octet-stream'
  };
}

// ---------- Delete a blob ----------
export async function deleteBlob(key) {
  if (!key) return;
  try {
    await store().delete(key);
  } catch (err) {
    console.error('[blob delete]', err.message);
  }
}

// ---------- Public URL for a blob key (served through /api/blob/:key) ----------
export function blobUrl(key) {
  if (!key) return '';
  return `/api/blob/${key}`;
}
