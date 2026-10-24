require('dotenv').config();
const { Pool, types } = require('pg');

types.setTypeParser(20, v => Number(v));

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is not set. Copy .env.example to .env and fill it in.');
  process.exit(1);
}

const local = /@(localhost|127\.0\.0\.1)/.test(url);

const pool = new Pool({
  connectionString: url,
  ssl: local ? false : { rejectUnauthorized: false },
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', e => console.error('pg pool error:', e.message));

async function tx(fn) {
  const c = await pool.connect();
  try {
    await c.query('begin');
    const out = await fn(c);
    await c.query('commit');
    return out;
  } catch (e) {
    try { await c.query('rollback'); } catch (_) {}
    throw e;
  } finally {
    c.release();
  }
}

module.exports = { pool, tx };
