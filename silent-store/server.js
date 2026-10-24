require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, tx } = require('./db');

const PORT = process.env.PORT || 3000;
const ADMIN_HASH = (process.env.ADMIN_HASH || '0dbb4d74e5a2fa63af1470dc8b4cab8da1be40360422a958668f9e2be6264190').toLowerCase();
const ADMIN_TTL = 8 * 36e5;
let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET is not set. Using a random one, so everyone is logged out on each restart.');
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '6mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}
const fail = (status, msg) => { throw new HttpError(status, msg); };
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const hits = new Map();
function limit(name, max, windowMs) {
  return (req, res, next) => {
    const k = name + ':' + req.ip;
    const now = Date.now();
    const rec = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (rec.length >= max) return res.status(429).json({ error: 'Too many attempts. Try again in a minute.' });
    rec.push(now);
    hits.set(k, rec);
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (!v.some(t => now - t < 600000)) hits.delete(k);
}, 300000).unref();

const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const safeEq = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const bearer = req => (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
const mask = n => (n ? n[0].toUpperCase() : '?') + '***';
const isImg = s => typeof s === 'string' && /^data:image\/(png|jpe?g|webp|gif);base64,/.test(s) && s.length < 4e6;
const int = (v, d = 0) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? n : d; };

async function getSettings(q = pool) {
  const r = await q.query(`select value from settings where key='store'`);
  const v = r.rows[0] ? r.rows[0].value : {};
  return { banner: v.banner || '', minTop: v.minTop || 500, pay: v.pay || {} };
}

const userAuth = wrap(async (req, res, next) => {
  const t = bearer(req);
  if (!t) fail(401, 'Please log in');
  let p;
  try { p = jwt.verify(t, SECRET); } catch (e) { fail(401, 'Session expired. Log in again.'); }
  if (p.role !== 'user') fail(401, 'Please log in');
  const r = await pool.query('select id, banned from users where id=$1', [p.uid]);
  if (!r.rows[0]) fail(401, 'Account not found');
  if (r.rows[0].banned) fail(403, 'This account has been suspended. Contact support.');
  req.uid = r.rows[0].id;
  next();
});

const adminAuth = (req, res, next) => {
  try {
    const p = jwt.verify(bearer(req), SECRET);
    if (p.role !== 'admin') throw new Error('x');
    next();
  } catch (e) {
    res.status(401).json({ error: 'Admin session expired' });
  }
};

/* ---------- shaping helpers ---------- */

async function loadProducts(q, { withKeys, includeHidden }) {
  const ps = (await q.query(
    `select id, name, game, descr, img, hot, hidden, sold from products ${includeHidden ? '' : 'where not hidden'} order by id desc`
  )).rows;
  if (!ps.length) return [];
  const ids = ps.map(p => p.id);
  const pls = (await q.query(
    `select pl.id, pl.product_id, pl.label, pl.price,
            (select count(*)::int from keys k where k.plan_id = pl.id) as stock
       from plans pl where pl.product_id = any($1) order by pl.position, pl.id`, [ids]
  )).rows;
  let keyMap = {};
  if (withKeys) {
    const ks = (await q.query(
      `select k.plan_id, k.value from keys k join plans pl on pl.id = k.plan_id
        where pl.product_id = any($1) order by k.id`, [ids]
    )).rows;
    for (const k of ks) (keyMap[k.plan_id] || (keyMap[k.plan_id] = [])).push(k.value);
  }
  return ps.map(p => {
    const plans = pls.filter(x => x.product_id === p.id).map(x => {
      const o = { id: x.id, label: x.label, price: x.price, stock: x.stock };
      if (withKeys) o.keys = keyMap[x.id] || [];
      return o;
    });
    return {
      id: p.id, name: p.name, game: p.game, desc: p.descr, img: p.img,
      hot: p.hot, hidden: p.hidden, sold: p.sold, plans,
      stock: plans.reduce((s, x) => s + x.stock, 0),
      price: plans.length ? Math.min(...plans.map(x => x.price)) : 0
    };
  });
}

async function userView(q, uid) {
  const u = (await q.query('select id, name, email, balance, spent, banned, since from users where id=$1', [uid])).rows[0];
  if (!u) return null;
  const keys = (await q.query(
    `select id, product_name, plan_label, game, key_value, at from orders where user_id=$1 order by at desc, id desc`, [uid]
  )).rows.map(o => ({
    id: o.id, name: o.product_name + (o.plan_label ? ' · ' + o.plan_label : ''),
    game: o.game, at: o.at, status: 'delivered', key: o.key_value
  }));
  const txs = (await q.query(
    `select title, amt, pending, rej, rid, at from wallet_txs where user_id=$1 order by at desc, id desc limit 50`, [uid]
  )).rows.map(t => ({ title: t.title, amt: t.amt, pending: t.pending, rej: t.rej, rid: t.rid, at: t.at }));
  const rank = (await q.query(`select count(*)::int + 1 as r from users where spent > $1`, [u.spent])).rows[0].r;
  return { id: u.id, name: u.name, email: u.email, bal: u.balance, spent: u.spent, banned: u.banned, since: u.since, keys, txs, rank };
}

async function checkCoupon(q, code, plan, uid, lock) {
  const c = (await q.query(
    `select * from coupons where code=$1 ${lock ? 'for update' : ''}`, [String(code || '').trim().toUpperCase()]
  )).rows[0];
  if (!c || !c.active) return { err: 'Invalid coupon code' };
  if (c.expires && Date.now() > c.expires) return { err: 'This coupon has expired' };
  if (c.max_uses && c.used >= c.max_uses) return { err: 'This coupon has reached its limit' };
  if (c.once && c.used_by.includes(uid)) return { err: 'You already used this coupon' };
  if (c.min_order && plan.price < c.min_order) return { err: 'Minimum order for this coupon is ₦' + c.min_order.toLocaleString('en-NG') };
  if (c.scope.length && !c.scope.includes(plan.product_id)) return { err: 'This coupon does not apply to this product' };
  const d = Math.min(plan.price, c.type === 'percent' ? Math.round(plan.price * c.value / 100) : c.value);
  return { c, d };
}

const sign = (payload, ttl) => jwt.sign(payload, SECRET, { expiresIn: ttl });

/* ---------- public / customer API ---------- */

app.get('/api/health', wrap(async (req, res) => {
  await pool.query('select 1');
  res.json({ ok: true });
}));

app.get('/api/store', wrap(async (req, res) => {
  const [products, settings, ord, board] = await Promise.all([
    loadProducts(pool, { withKeys: false, includeHidden: false }),
    getSettings(),
    pool.query('select uname, product_name from orders order by at desc, id desc limit 8'),
    pool.query('select id, name, spent from users where spent > 0 and not banned order by spent desc limit 5')
  ]);
  res.json({
    products,
    settings,
    orders: ord.rows.map(o => ({ n: mask(o.uname), p: o.product_name })),
    board: board.rows.map(b => ({ id: b.id, n: mask(b.name), a: b.spent }))
  });
}));

const NAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;
const EMAIL_RE = /^\S+@\S+\.\S+$/;

app.post('/api/auth/signup', limit('signup', 10, 600000), wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  const email = String((req.body || {}).email || '').trim().slice(0, 120);
  const pass = String((req.body || {}).password || '');
  if (!NAME_RE.test(name)) fail(400, 'Username must be 3-20 letters, numbers, dots, dashes or underscores.');
  if (!EMAIL_RE.test(email)) fail(400, 'Enter a valid email address.');
  if (pass.length < 6 || pass.length > 100) fail(400, 'Password needs at least 6 characters.');
  const hash = await bcrypt.hash(pass, 10);
  let r;
  try {
    r = await pool.query(
      `insert into users(username, name, email, pass_hash, since) values($1,$2,$3,$4,$5) returning id`,
      [name.toLowerCase(), name, email, hash, Date.now()]
    );
  } catch (e) {
    if (e.code === '23505') fail(409, 'That username is taken.');
    throw e;
  }
  res.json({ token: sign({ uid: r.rows[0].id, role: 'user' }, '30d') });
}));

app.post('/api/auth/login', limit('login', 15, 600000), wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().toLowerCase();
  const pass = String((req.body || {}).password || '');
  const r = await pool.query('select id, pass_hash, banned from users where username=$1', [name]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(pass, u.pass_hash))) fail(401, 'Username or password is incorrect.');
  if (u.banned) fail(403, 'This account has been suspended. Contact support.');
  res.json({ token: sign({ uid: u.id, role: 'user' }, '30d') });
}));

app.get('/api/me', userAuth, wrap(async (req, res) => {
  res.json(await userView(pool, req.uid));
}));

app.post('/api/coupons/check', userAuth, wrap(async (req, res) => {
  const pl = (await pool.query('select id, product_id, price from plans where id=$1', [int(req.body.planId)])).rows[0];
  if (!pl) fail(404, 'Product not found');
  const r = await checkCoupon(pool, req.body.code, pl, req.uid, false);
  if (r.err) fail(400, r.err);
  res.json({ code: r.c.code, discount: r.d });
}));

app.post('/api/buy', userAuth, wrap(async (req, res) => {
  const planId = int(req.body.planId);
  const couponCode = String(req.body.coupon || '').trim();
  const code = await tx(async c => {
    const u = (await c.query('select id, name, balance, banned from users where id=$1 for update', [req.uid])).rows[0];
    if (!u || u.banned) fail(403, 'This account has been suspended. Contact support.');
    const pl = (await c.query(
      `select pl.id, pl.product_id, pl.label, pl.price, p.name, p.game, p.hidden
         from plans pl join products p on p.id = pl.product_id where pl.id=$1`, [planId]
    )).rows[0];
    if (!pl || pl.hidden) fail(404, 'This product is no longer available');
    let d = 0, cp = null;
    if (couponCode) {
      const r = await checkCoupon(c, couponCode, pl, u.id, true);
      if (r.err) fail(400, r.err);
      cp = r.c; d = r.d;
    }
    const total = pl.price - d;
    if (u.balance < total) fail(402, 'Not enough funds');
    const k = (await c.query(
      'select id, value from keys where plan_id=$1 order by id limit 1 for update skip locked', [pl.id]
    )).rows[0];
    if (!k) fail(409, 'Sold out');
    await c.query('delete from keys where id=$1', [k.id]);
    await c.query('update users set balance = balance - $1, spent = spent + $1 where id=$2', [total, u.id]);
    await c.query('update products set sold = sold + 1 where id=$1', [pl.product_id]);
    if (cp) await c.query('update coupons set used = used + 1, used_by = array_append(used_by, $1) where code=$2', [u.id, cp.code]);
    const now = Date.now();
    const oc = 'O' + now.toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
    const label = pl.name + (pl.label ? ' · ' + pl.label : '');
    await c.query(
      `insert into orders(code, user_id, uname, product_name, game, plan_label, price, paid, coupon, key_value, at)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [oc, u.id, u.name, pl.name, pl.game, pl.label, pl.price, total, cp ? cp.code : '', k.value, now]
    );
    await c.query('insert into wallet_txs(user_id, title, amt, at) values($1,$2,$3,$4)', [u.id, 'Bought ' + label, -total, now]);
    return oc;
  });
  res.json({ ok: true, order: code });
}));

app.post('/api/topups', userAuth, limit('topup', 20, 600000), wrap(async (req, res) => {
  const amount = int(req.body.amount);
  const settings = await getSettings();
  if (amount < settings.minTop) fail(400, 'Minimum top-up is ₦' + settings.minTop.toLocaleString('en-NG'));
  if (amount > 1000000) fail(400, 'Maximum top-up is ₦1,000,000');
  if (!isImg(req.body.shot)) fail(400, 'Upload a valid receipt image');
  const ref = await tx(async c => {
    const u = (await c.query('select id, name from users where id=$1 for update', [req.uid])).rows[0];
    const pend = (await c.query(`select count(*)::int n from topups where user_id=$1 and status='pending'`, [u.id])).rows[0].n;
    if (pend >= 5) fail(429, 'You have too many pending requests. Wait for the admin to review them.');
    const now = Date.now();
    const given = String(req.body.ref || '');
    const id = /^SH[A-Z0-9]{6,16}$/.test(given)
      ? given
      : 'SH' + now.toString(36).toUpperCase() + crypto.randomBytes(1).toString('hex').toUpperCase();
    const dup = (await c.query('select 1 from topups where id=$1', [id])).rowCount;
    if (dup) fail(409, 'Duplicate request. Try again.');
    await c.query(
      `insert into topups(id, user_id, name, amount, shot, at) values($1,$2,$3,$4,$5,$6)`,
      [id, u.id, u.name, amount, req.body.shot, now]
    );
    await c.query(
      `insert into wallet_txs(user_id, title, amt, pending, rid, at) values($1,'Top-up by transfer',$2,true,$3,$4)`,
      [u.id, amount, id, now]
    );
    return id;
  });
  res.json({ ref });
}));

/* ---------- admin API ---------- */

app.post('/api/admin/login', limit('admin', 6, 60000), wrap(async (req, res) => {
  const ok = safeEq(sha(String((req.body || {}).code || '').trim()), ADMIN_HASH);
  if (!ok) fail(401, 'Invalid access code.');
  const until = Date.now() + ADMIN_TTL;
  res.json({ token: sign({ role: 'admin' }, Math.floor(ADMIN_TTL / 1000)), until });
}));

app.get('/api/admin/state', adminAuth, wrap(async (req, res) => {
  const [products, settings, coupons, requests, orders, users] = await Promise.all([
    loadProducts(pool, { withKeys: true, includeHidden: true }),
    getSettings(),
    pool.query('select * from coupons order by created desc'),
    pool.query('select id, user_id, name, amount, status, at from topups order by at desc limit 500'),
    pool.query('select * from orders order by at desc, id desc limit 5000'),
    pool.query(
      `select u.id, u.name, u.email, u.balance, u.spent, u.banned, u.since,
              (select count(*)::int from orders o where o.user_id = u.id) as orders
         from users u order by u.id desc`
    )
  ]);
  const data = {};
  for (const u of users.rows) {
    data[u.id] = { name: u.name, email: u.email, bal: u.balance, spent: u.spent, banned: u.banned, since: u.since, orders: u.orders };
  }
  res.json({
    products,
    settings,
    coupons: coupons.rows.map(c => ({
      code: c.code, type: c.type, value: c.value, min: c.min_order, max: c.max_uses, used: c.used,
      expires: c.expires, once: c.once, active: c.active, scope: c.scope
    })),
    requests: requests.rows.map(r => ({ id: r.id, user: r.user_id, name: r.name, amt: r.amount, status: r.status, at: r.at })),
    orders: orders.rows.map(o => ({
      id: o.code, n: mask(o.uname), p: o.product_name, plan: o.plan_label, user: o.user_id, uname: o.uname,
      price: o.price, paid: o.paid, coupon: o.coupon, key: o.key_value, at: o.at
    })),
    data
  });
}));

function parseProduct(b) {
  const name = String(b.name || '').trim().slice(0, 120);
  const game = String(b.game || '').trim().slice(0, 60);
  if (!isImg(b.img)) fail(400, 'Add a product image');
  if (!name || !game) fail(400, 'Name and game are required');
  if (!Array.isArray(b.plans) || !b.plans.length || b.plans.length > 20) fail(400, 'Add at least one price');
  const seen = new Set();
  const plans = b.plans.map(p => {
    const label = String(p.label || '').trim().slice(0, 40);
    const price = int(p.price);
    if (!(price > 0)) fail(400, 'Enter a price above 0');
    if (seen.has(label.toLowerCase())) fail(400, 'Each duration must be different');
    seen.add(label.toLowerCase());
    const keys = [...new Set((Array.isArray(p.keys) ? p.keys : []).map(k => String(k).trim()).filter(Boolean))];
    if (keys.some(k => k.length > 500)) fail(400, 'A key is too long');
    return { label, price, keys };
  });
  return { name, game, desc: String(b.desc || '').trim().slice(0, 500), img: b.img, hot: !!b.hot, hidden: !!b.hidden, plans };
}

async function writePlans(c, productId, plans) {
  await c.query('delete from plans where product_id=$1', [productId]);
  for (const [i, p] of plans.entries()) {
    const pl = (await c.query(
      'insert into plans(product_id, label, price, position) values($1,$2,$3,$4) returning id', [productId, p.label, p.price, i]
    )).rows[0];
    if (p.keys.length) {
      await c.query('insert into keys(plan_id, value) select $1, unnest($2::text[])', [pl.id, p.keys]);
    }
  }
}

app.post('/api/admin/products', adminAuth, wrap(async (req, res) => {
  const p = parseProduct(req.body || {});
  const id = await tx(async c => {
    const r = await c.query(
      `insert into products(name, game, descr, img, hot, hidden, created) values($1,$2,$3,$4,$5,$6,$7) returning id`,
      [p.name, p.game, p.desc, p.img, p.hot, p.hidden, Date.now()]
    );
    await writePlans(c, r.rows[0].id, p.plans);
    return r.rows[0].id;
  });
  res.json({ id });
}));

app.put('/api/admin/products/:id', adminAuth, wrap(async (req, res) => {
  const p = parseProduct(req.body || {});
  const id = int(req.params.id);
  await tx(async c => {
    const r = await c.query(
      `update products set name=$1, game=$2, descr=$3, img=$4, hot=$5, hidden=$6 where id=$7 returning id`,
      [p.name, p.game, p.desc, p.img, p.hot, p.hidden, id]
    );
    if (!r.rowCount) fail(404, 'Product not found');
    await writePlans(c, id, p.plans);
  });
  res.json({ ok: true });
}));

app.patch('/api/admin/products/:id', adminAuth, wrap(async (req, res) => {
  const r = await pool.query('update products set hidden=$1 where id=$2', [!!req.body.hidden, int(req.params.id)]);
  if (!r.rowCount) fail(404, 'Product not found');
  res.json({ ok: true });
}));

app.delete('/api/admin/products/:id', adminAuth, wrap(async (req, res) => {
  await pool.query('delete from products where id=$1', [int(req.params.id)]);
  res.json({ ok: true });
}));

app.get('/api/admin/requests/:id/shot', adminAuth, wrap(async (req, res) => {
  const r = await pool.query('select shot from topups where id=$1', [req.params.id]);
  if (!r.rows[0]) fail(404, 'Request not found');
  res.json({ shot: r.rows[0].shot });
}));

app.post('/api/admin/requests/:id/decide', adminAuth, wrap(async (req, res) => {
  const ok = !!req.body.ok;
  const out = await tx(async c => {
    const r = (await c.query('select * from topups where id=$1 for update', [req.params.id])).rows[0];
    if (!r) fail(404, 'Request not found');
    if (r.status !== 'pending') fail(409, 'Already ' + r.status);
    await c.query('update topups set status=$1 where id=$2', [ok ? 'approved' : 'rejected', r.id]);
    await c.query(
      `update wallet_txs set pending=false, rej=$1, title=$2 where rid=$3`,
      [!ok, ok ? 'Top-up approved' : 'Top-up rejected', r.id]
    );
    if (ok) await c.query('update users set balance = balance + $1 where id=$2', [r.amount, r.user_id]);
    return { amt: r.amount, name: r.name };
  });
  res.json(out);
}));

function parseCoupon(b) {
  const code = String(b.code || '').trim().toUpperCase();
  const type = b.type === 'fixed' ? 'fixed' : 'percent';
  const value = int(b.value);
  if (!/^[A-Z0-9-]{3,20}$/.test(code)) fail(400, 'Code must be 3-20 letters, numbers or dashes');
  if (!(value > 0) || (type === 'percent' && value > 100)) fail(400, type === 'percent' ? 'Percent must be 1 to 100' : 'Enter an amount above 0');
  return {
    code, type, value,
    min: Math.max(0, int(b.min)), max: Math.max(0, int(b.max)), expires: Math.max(0, int(b.expires)),
    once: !!b.once, scope: (Array.isArray(b.scope) ? b.scope : []).map(x => int(x)).filter(x => x > 0)
  };
}

app.post('/api/admin/coupons', adminAuth, wrap(async (req, res) => {
  const c = parseCoupon(req.body || {});
  const orig = String((req.body || {}).original || '').trim().toUpperCase();
  try {
    if (orig) {
      const r = await pool.query(
        `update coupons set code=$1, type=$2, value=$3, min_order=$4, max_uses=$5, expires=$6, once=$7, scope=$8 where code=$9`,
        [c.code, c.type, c.value, c.min, c.max, c.expires, c.once, c.scope, orig]
      );
      if (!r.rowCount) fail(404, 'Coupon not found');
    } else {
      await pool.query(
        `insert into coupons(code, type, value, min_order, max_uses, expires, once, scope, created) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [c.code, c.type, c.value, c.min, c.max, c.expires, c.once, c.scope, Date.now()]
      );
    }
  } catch (e) {
    if (e.code === '23505') fail(409, 'That code already exists');
    throw e;
  }
  res.json({ ok: true });
}));

app.patch('/api/admin/coupons/:code', adminAuth, wrap(async (req, res) => {
  await pool.query('update coupons set active = not active where code=$1', [req.params.code]);
  res.json({ ok: true });
}));

app.delete('/api/admin/coupons/:code', adminAuth, wrap(async (req, res) => {
  await pool.query('delete from coupons where code=$1', [req.params.code]);
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/wallet', adminAuth, wrap(async (req, res) => {
  const n = int(req.body.amt);
  if (!n) fail(400, 'Enter an amount');
  const note = String(req.body.note || '').trim().slice(0, 80) || 'Admin adjustment';
  await tx(async c => {
    const u = (await c.query('select id, balance from users where id=$1 for update', [int(req.params.id)])).rows[0];
    if (!u) fail(404, 'Customer not found');
    if (u.balance + n < 0) fail(400, 'That would make the balance negative');
    await c.query('update users set balance = balance + $1 where id=$2', [n, u.id]);
    await c.query('insert into wallet_txs(user_id, title, amt, at) values($1,$2,$3,$4)', [u.id, note, n, Date.now()]);
  });
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/ban', adminAuth, wrap(async (req, res) => {
  const r = await pool.query('update users set banned = not banned where id=$1 returning banned', [int(req.params.id)]);
  if (!r.rowCount) fail(404, 'Customer not found');
  res.json({ banned: r.rows[0].banned });
}));

app.put('/api/admin/settings', adminAuth, wrap(async (req, res) => {
  const b = req.body || {};
  const wa = String((b.pay || {}).wa || '').replace(/\D/g, '');
  if (!wa) fail(400, 'Enter a WhatsApp number');
  const val = {
    banner: String(b.banner || '').trim().slice(0, 200),
    minTop: Math.max(1, int(b.minTop, 500)),
    pay: {
      bank: String((b.pay || {}).bank || '').trim().slice(0, 60),
      acct: String((b.pay || {}).acct || '').trim().slice(0, 30),
      name: String((b.pay || {}).name || '').trim().slice(0, 80),
      wa
    }
  };
  await pool.query(
    `insert into settings(key, value) values('store', $1) on conflict (key) do update set value = excluded.value`,
    [JSON.stringify(val)]
  );
  res.json({ ok: true });
}));

/* ---------- static frontend ---------- */

const pub = path.join(__dirname, 'public');
app.get('/admin', (req, res) => res.sendFile(path.join(pub, 'admin.html')));
app.use(express.static(pub, { extensions: ['html'] }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Image is too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Try again.' });
});

if (require.main === module) {
  app.listen(PORT, () => console.log('Silent H4X store running on port ' + PORT));
}

module.exports = app;
