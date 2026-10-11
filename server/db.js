import pg from 'pg';

const { Pool } = pg;

// Neon requires SSL and single connection per Lambda
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('neon.tech')
    ? { rejectUnauthorized: false }
    : false,
  max: 3,                     // Lambda containers are short-lived
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 8_000
});

// Helper: run a query with automatic client management
export async function q(text, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

// Helper: transaction
export async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function ping() {
  await q('SELECT 1');
}
