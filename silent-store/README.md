# SILENT H4X store

Express + Supabase Postgres backend for the vault (customer store) and admin pages.

## Run

    npm install
    npm run setup     # creates the tables in Supabase (safe to run again)
    npm start         # http://localhost:3000  (admin at /admin)

Your existing admin access code still works. To change it, set `ADMIN_HASH` to the SHA-256 of the new code.

## Deploy (Render, Railway)

Build command `npm install`, start command `npm start`, then add `DATABASE_URL` and `JWT_SECRET` as environment variables. Run `npm run setup` once (locally is fine, it talks to Supabase).

If you host the HTML on Vercel or Netlify instead, add this line in the `<head>` of both pages before the main script, and set `CORS_ORIGIN` on the server:

    <script>window.SH4X_API='https://your-api.onrender.com'</script>

## What moved to the server

- Accounts: bcrypt passwords, signed login tokens, bans enforced on every request
- Keys never leave the server until bought; buying is one database transaction (balance, key, coupon, order), so two people can never get the same key
- Top-ups, approvals, wallet adjustments, coupons, orders, settings
- All tables have row level security on, so Supabase's public API cannot read them. Only this server can.
