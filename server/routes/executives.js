import express from 'express';
import multer from 'multer';
import { q } from '../db.js';
import { requireAuth, requireRole, csrfProtect, auditLog } from '../middleware.js';
import { uploadImage, deleteBlob, blobUrl } from '../blobs.js';
import { sanitizeHtml } from '../sanitize.js';

export const executivesRouter = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('unsupported_image_type'));
    cb(null, true);
  }
});

// ---------- Public list ----------
executivesRouter.get('/', async (req, res, next) => {
  try {
    const { rows } = await q(`
      SELECT id, name, role, position_order, bio, email, linkedin, phone,
             photo_blob_key, photo_thumb_key, term, is_current
      FROM executives
      WHERE status = 'published'
      ORDER BY is_current DESC, position_order ASC, id ASC
    `);
    // Attach public URLs
    const out = rows.map(r => ({
      ...r,
      photo_path: blobUrl(r.photo_blob_key),
      photo_thumb: blobUrl(r.photo_thumb_key)
    }));
    res.setHeader('Cache-Control', 'public, max-age=120');
    res.json(out);
  } catch (err) { next(err); }
});

// ---------- Create (admin) ----------
executivesRouter.post('/',
  requireAuth, requireRole('admin', 'editor'), csrfProtect,
  upload.single('photo'),
  auditLog('executive_created'),
  async (req, res, next) => {
    try {
      const b = req.body;
      if (!b.name || !b.role) return res.status(400).json({ error: 'missing_fields' });

      let photo_blob_key = '', photo_thumb_key = '';
      if (req.file) {
        const p = await uploadImage(req.file.buffer, 'executives', { maxWidth: 1200, thumbSize: 480 });
        photo_blob_key = p.blobKey;
        photo_thumb_key = p.thumbKey;
      }

      const now = Date.now();
      const { rows } = await q(`
        INSERT INTO executives
          (name, role, position_order, bio, email, linkedin, phone,
           photo_blob_key, photo_thumb_key, term, is_current, status, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        RETURNING *
      `, [
        String(b.name).slice(0, 120),
        String(b.role).slice(0, 80),
        Number(b.position_order) || 100,
        sanitizeHtml(b.bio || ''),
        String(b.email || '').slice(0, 200),
        String(b.linkedin || '').slice(0, 300),
        String(b.phone || '').slice(0, 40),
        photo_blob_key,
        photo_thumb_key,
        String(b.term || '').slice(0, 40),
        b.is_current === 'false' ? false : true,
        ['draft','published','archived'].includes(b.status) ? b.status : 'published',
        now, now
      ]);

      res.status(201).json({
        ...rows[0],
        photo_path: blobUrl(rows[0].photo_blob_key),
        photo_thumb: blobUrl(rows[0].photo_thumb_key)
      });
    } catch (err) { next(err); }
  }
);

// ---------- Update ----------
executivesRouter.put('/:id',
  requireAuth, requireRole('admin', 'editor'), csrfProtect,
  upload.single('photo'),
  auditLog('executive_updated'),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const { rows: existingRows } = await q('SELECT * FROM executives WHERE id = $1', [id]);
      const existing = existingRows[0];
      if (!existing) return res.status(404).json({ error: 'not_found' });

      const b = req.body;
      let photo_blob_key = existing.photo_blob_key;
      let photo_thumb_key = existing.photo_thumb_key;

      if (req.file) {
        const p = await uploadImage(req.file.buffer, 'executives', { maxWidth: 1200, thumbSize: 480 });
        photo_blob_key = p.blobKey;
        photo_thumb_key = p.thumbKey;
        // delete old blobs (fire and forget)
        deleteBlob(existing.photo_blob_key).catch(() => {});
        deleteBlob(existing.photo_thumb_key).catch(() => {});
      }

      const { rows } = await q(`
        UPDATE executives SET
          name = COALESCE($1, name),
          role = COALESCE($2, role),
          position_order = COALESCE($3, position_order),
          bio = COALESCE($4, bio),
          email = COALESCE($5, email),
          linkedin = COALESCE($6, linkedin),
          phone = COALESCE($7, phone),
          photo_blob_key = $8,
          photo_thumb_key = $9,
          term = COALESCE($10, term),
          is_current = COALESCE($11, is_current),
          status = COALESCE($12, status),
          updated_at = $13
        WHERE id = $14
        RETURNING *
      `, [
        b.name ? String(b.name).slice(0,120) : null,
        b.role ? String(b.role).slice(0,80) : null,
        b.position_order ? Number(b.position_order) : null,
        b.bio !== undefined ? sanitizeHtml(b.bio) : null,
        b.email !== undefined ? String(b.email).slice(0,200) : null,
        b.linkedin !== undefined ? String(b.linkedin).slice(0,300) : null,
        b.phone !== undefined ? String(b.phone).slice(0,40) : null,
        photo_blob_key,
        photo_thumb_key,
        b.term !== undefined ? String(b.term).slice(0,40) : null,
        b.is_current !== undefined ? (b.is_current === 'false' ? false : true) : null,
        ['draft','published','archived'].includes(b.status) ? b.status : null,
        Date.now(), id
      ]);

      res.json({
        ...rows[0],
        photo_path: blobUrl(rows[0].photo_blob_key),
        photo_thumb: blobUrl(rows[0].photo_thumb_key)
      });
    } catch (err) { next(err); }
  }
);

// ---------- Delete ----------
executivesRouter.delete('/:id',
  requireAuth, requireRole('admin'), csrfProtect, auditLog('executive_deleted'),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const { rows } = await q('SELECT photo_blob_key, photo_thumb_key FROM executives WHERE id = $1', [id]);
      if (!rows[0]) return res.status(404).json({ error: 'not_found' });
      deleteBlob(rows[0].photo_blob_key).catch(() => {});
      deleteBlob(rows[0].photo_thumb_key).catch(() => {});
      await q('DELETE FROM executives WHERE id = $1', [id]);
      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);
