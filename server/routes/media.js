import express from 'express';
import multer from 'multer';
import { q } from '../db.js';
import { requireAuth, requireRole, csrfProtect, auditLog } from '../middleware.js';
import { uploadImage, deleteBlob, blobUrl } from '../blobs.js';
import { sanitizeHtml } from '../sanitize.js';

export const mediaRouter = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('unsupported_image_type'));
    cb(null, true);
  }
});

// ---------- Public list ----------
mediaRouter.get('/', async (req, res, next) => {
  try {
    const kind = req.query.kind === 'video' ? 'video' : req.query.kind === 'photo' ? 'photo' : null;
    const album = typeof req.query.album === 'string' ? req.query.album.slice(0, 80) : null;
    const limit = Math.min(Number(req.query.limit) || 60, 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const cond = [`status = 'published'`];
    const params = [];
    let i = 1;
    if (kind) { cond.push(`kind = $${i++}`); params.push(kind); }
    if (album) { cond.push(`album = $${i++}`); params.push(album); }
    params.push(limit, offset);

    const { rows } = await q(`
      SELECT id, kind, title, caption, album, blob_key, thumb_blob_key,
             youtube_id, width, height, duration_seconds, taken_at, created_at
      FROM media
      WHERE ${cond.join(' AND ')}
      ORDER BY COALESCE(taken_at, created_at) DESC
      LIMIT $${i++} OFFSET $${i++}
    `, params);

    const total = Number((await q(
      `SELECT COUNT(*) c FROM media WHERE ${cond.join(' AND ')}`,
      params.slice(0, params.length - 2)
    )).rows[0].c);

    res.setHeader('Cache-Control', 'public, max-age=60');
    res.json({
      rows: rows.map(r => ({
        ...r,
        file_path: r.kind === 'photo' ? blobUrl(r.blob_key) : '',
        thumb_path: blobUrl(r.thumb_blob_key),
        youtube_url: r.youtube_id ? `https://www.youtube.com/embed/${r.youtube_id}` : '',
        poster_path: r.youtube_id ? `https://i.ytimg.com/vi/${r.youtube_id}/hqdefault.jpg` : ''
      })),
      total, limit, offset
    });
  } catch (err) { next(err); }
});

// ---------- Upload photos (multi) ----------
mediaRouter.post('/photos',
  requireAuth, requireRole('admin', 'editor'), csrfProtect,
  upload.array('photos', 20),
  auditLog('media_photos_uploaded'),
  async (req, res, next) => {
    try {
      if (!req.files?.length) return res.status(400).json({ error: 'no_files' });
      const { title = 'Untitled', caption = '', album = 'General' } = req.body;
      const now = Date.now();
      const inserted = [];

      for (const f of req.files) {
        const p = await uploadImage(f.buffer, 'gallery/photos', { maxWidth: 2400, thumbSize: 720 });
        const { rows } = await q(`
          INSERT INTO media
            (kind, title, caption, album, blob_key, thumb_blob_key, mime,
             width, height, file_size, uploaded_by, status, created_at)
          VALUES ('photo', $1,$2,$3,$4,$5,'image/webp',$6,$7,$8,$9,'published',$10)
          RETURNING *
        `, [
          String(title).slice(0, 200),
          sanitizeHtml(String(caption).slice(0, 800)),
          String(album).slice(0, 80),
          p.blobKey, p.thumbKey,
          p.width, p.height, p.size,
          req.user.id, now
        ]);
        inserted.push({
          ...rows[0],
          file_path: blobUrl(rows[0].blob_key),
          thumb_path: blobUrl(rows[0].thumb_blob_key)
        });
      }
      res.status(201).json(inserted);
    } catch (err) { next(err); }
  }
);

// ---------- Add video by YouTube ID/URL ----------
mediaRouter.post('/videos',
  requireAuth, requireRole('admin', 'editor'), csrfProtect,
  auditLog('media_video_added'),
  async (req, res, next) => {
    try {
      const { title, caption = '', album = 'General', youtube } = req.body;
      if (!title) return res.status(400).json({ error: 'missing_title' });

      const id = extractYouTubeId(youtube);
      if (!id) return res.status(400).json({ error: 'invalid_youtube_url' });

      const { rows } = await q(`
        INSERT INTO media
          (kind, title, caption, album, youtube_id, uploaded_by, status, created_at)
        VALUES ('video', $1,$2,$3,$4,$5,'published',$6)
        RETURNING *
      `, [
        String(title).slice(0, 200),
        sanitizeHtml(String(caption).slice(0, 800)),
        String(album).slice(0, 80),
        id, req.user.id, Date.now()
      ]);

      res.status(201).json({
        ...rows[0],
        youtube_url: `https://www.youtube.com/embed/${id}`,
        poster_path: `https://i.ytimg.com/vi/${id}/hqdefault.jpg`
      });
    } catch (err) { next(err); }
  }
);

// ---------- Update metadata ----------
mediaRouter.put('/:id',
  requireAuth, requireRole('admin', 'editor'), csrfProtect, auditLog('media_updated'),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const { title, caption, album, status } = req.body;
      const { rows } = await q(`
        UPDATE media SET
          title = COALESCE($1, title),
          caption = COALESCE($2, caption),
          album = COALESCE($3, album),
          status = COALESCE($4, status)
        WHERE id = $5 RETURNING *
      `, [
        title ? String(title).slice(0,200) : null,
        caption !== undefined ? sanitizeHtml(String(caption).slice(0,800)) : null,
        album ? String(album).slice(0,80) : null,
        ['draft','published','archived'].includes(status) ? status : null,
        id
      ]);
      if (!rows[0]) return res.status(404).json({ error: 'not_found' });
      res.json(rows[0]);
    } catch (err) { next(err); }
  }
);

// ---------- Delete ----------
mediaRouter.delete('/:id',
  requireAuth, requireRole('admin'), csrfProtect, auditLog('media_deleted'),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const { rows } = await q('SELECT blob_key, thumb_blob_key FROM media WHERE id = $1', [id]);
      if (!rows[0]) return res.status(404).json({ error: 'not_found' });
      deleteBlob(rows[0].blob_key).catch(() => {});
      deleteBlob(rows[0].thumb_blob_key).catch(() => {});
      await q('DELETE FROM media WHERE id = $1', [id]);
      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

function extractYouTubeId(input) {
  if (!input) return null;
  const s = String(input).trim();
  if (/^[A-Za-z0-9_-]{11}$/.test(s)) return s;              // raw ID
  const m = s.match(/(?:youtu\.be\/|v=|\/embed\/|\/shorts\/)([A-Za-z0-9_-]{11})/);
  return m ? m[1] : null;
}
