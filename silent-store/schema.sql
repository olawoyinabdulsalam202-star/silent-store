create table if not exists users (
  id serial primary key,
  username text not null unique,
  name text not null,
  email text not null,
  pass_hash text not null,
  balance bigint not null default 0 check (balance >= 0),
  spent bigint not null default 0,
  banned boolean not null default false,
  since bigint not null
);

create table if not exists products (
  id serial primary key,
  name text not null,
  game text not null,
  descr text not null default '',
  img text not null,
  hot boolean not null default false,
  hidden boolean not null default false,
  sold integer not null default 0,
  created bigint not null
);

create table if not exists plans (
  id serial primary key,
  product_id integer not null references products(id) on delete cascade,
  label text not null default '',
  price integer not null check (price > 0),
  position integer not null default 0
);
create index if not exists plans_product_idx on plans(product_id);

create table if not exists keys (
  id serial primary key,
  plan_id integer not null references plans(id) on delete cascade,
  value text not null
);
create index if not exists keys_plan_idx on keys(plan_id);

create table if not exists orders (
  id serial primary key,
  code text not null unique,
  user_id integer references users(id) on delete set null,
  uname text not null,
  product_name text not null,
  game text not null default '',
  plan_label text not null default '',
  price integer not null,
  paid integer not null,
  coupon text not null default '',
  key_value text not null,
  at bigint not null
);
create index if not exists orders_user_idx on orders(user_id);
create index if not exists orders_at_idx on orders(at desc);

create table if not exists topups (
  id text primary key,
  user_id integer not null references users(id) on delete cascade,
  name text not null,
  amount integer not null check (amount > 0),
  shot text not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  at bigint not null
);
create index if not exists topups_status_idx on topups(status, at desc);

create table if not exists wallet_txs (
  id serial primary key,
  user_id integer not null references users(id) on delete cascade,
  title text not null,
  amt integer not null,
  pending boolean not null default false,
  rej boolean not null default false,
  rid text,
  at bigint not null
);
create index if not exists wallet_txs_user_idx on wallet_txs(user_id, at desc);

create table if not exists coupons (
  code text primary key,
  type text not null check (type in ('percent','fixed')),
  value integer not null check (value > 0),
  min_order integer not null default 0,
  max_uses integer not null default 0,
  used integer not null default 0,
  expires bigint not null default 0,
  once boolean not null default true,
  active boolean not null default true,
  scope integer[] not null default '{}',
  used_by integer[] not null default '{}',
  created bigint not null
);

create table if not exists settings (
  key text primary key,
  value jsonb not null
);

alter table users enable row level security;
alter table products enable row level security;
alter table plans enable row level security;
alter table keys enable row level security;
alter table orders enable row level security;
alter table topups enable row level security;
alter table wallet_txs enable row level security;
alter table coupons enable row level security;
alter table settings enable row level security;
