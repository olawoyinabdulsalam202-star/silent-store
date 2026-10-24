require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { pool } = require('../db');

(async () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  try {
    await pool.query(sql);
    await pool.query(
      `insert into settings(key, value) values('store', $1) on conflict (key) do nothing`,
      [JSON.stringify({ banner: '', minTop: 500, pay: {} })]
    );
    const r = await pool.query(
      `select table_name from information_schema.tables where table_schema='public' order by 1`
    );
    console.log('Tables ready:', r.rows.map(x => x.table_name).join(', '));
  } catch (e) {
    console.error('Setup failed:', e.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
