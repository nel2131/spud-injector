// SpudLoader auth + script proxy - Render.com + PostgreSQL.
//
// Routes:
//   POST /api/auth          {key, hwid}        -> {status, token?}   (403 on bad key/hwid)
//   GET  /scripts/<path>    Authorization: Bearer <token>            (401 on bad token)
//
// The token is a self-contained HMAC-signed string: <hwid>.<expUnix>.<base64url(sig)>.
// No token table - verify = recompute the HMAC and compare in constant time.
//
// Env (set in Render dashboard):
//   DATABASE_URL     - postgres connection string (Render Postgres)
//   SIGNING_SECRET   - long random string (e.g. `openssl rand -hex 32`) - do NOT ship this to clients
//   PORT             - Render sets this
//
// Table (run once against DATABASE_URL):
//   CREATE TABLE licenses ( key TEXT PRIMARY KEY, hwid TEXT );
//   INSERT INTO licenses (key) VALUES ('EXAMPLE-KEY-1');
//
// Scripts live in ./scripts next to this file - they ship with the deploy.
// Folder tree: scripts/manifest.json, scripts/Invoker/combo.lua, scripts/Universal/x.lua ...

const express = require('express');
const path    = require('path');
const crypto  = require('crypto');
const { Pool } = require('pg');

const SECRET = process.env.SIGNING_SECRET || '';
if (!SECRET) { console.error('SIGNING_SECRET missing - refusing to start'); process.exit(1); }

const TOKEN_TTL_SEC = 24 * 60 * 60;   // one day; user re-logs in after that

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

function b64url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(hwid, exp) {
    return b64url(crypto.createHmac('sha256', SECRET).update(`${hwid}.${exp}`).digest());
}

function mintToken(hwid) {
    const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;
    return `${hwid}.${exp}.${sign(hwid, exp)}`;
}

function verifyToken(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [hwid, expStr, sig] = parts;
    const exp = Number(expStr);
    if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return null;
    const expected = sign(hwid, exp);
    const a = Buffer.from(sig), b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return hwid;
}

const app = express();
app.use(express.json({ limit: '4kb' }));

app.get('/', (_req, res) => res.send('SpudLoader auth up.'));

app.post('/api/auth', async (req, res) => {
    const key  = typeof req.body?.key  === 'string' ? req.body.key.trim()  : '';
    const hwid = typeof req.body?.hwid === 'string' ? req.body.hwid.trim() : '';
    if (!key || !hwid) return res.status(400).json({ status: 'bad_request' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const { rows } = await client.query(
            'SELECT hwid FROM licenses WHERE key = $1 FOR UPDATE',
            [key]
        );
        if (rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(403).json({ status: 'unauthorized' });
        }
        const bound = rows[0].hwid;
        if (bound === null) {
            await client.query('UPDATE licenses SET hwid = $1 WHERE key = $2', [hwid, key]);
            await client.query('COMMIT');
            return res.json({ status: 'authorized', token: mintToken(hwid) });
        }
        if (bound === hwid) {
            await client.query('COMMIT');
            return res.json({ status: 'authorized', token: mintToken(hwid) });
        }
        await client.query('ROLLBACK');
        return res.status(403).json({ status: 'unauthorized' });
    } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('auth error', e);
        return res.status(500).json({ status: 'error' });
    } finally {
        client.release();
    }
});

// --- gated static server for ./scripts ---
function bearer(req) {
    const h = req.headers['authorization'];
    if (!h || typeof h !== 'string' || !h.startsWith('Bearer ')) return null;
    return h.slice(7).trim();
}

app.use('/scripts', (req, res, next) => {
    const token = bearer(req);
    if (!token || !verifyToken(token)) return res.status(401).json({ status: 'unauthorized' });
    next();
}, express.static(path.join(__dirname, 'scripts'), {
    fallthrough: false,
    dotfiles: 'deny',
    index: false,
}));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`SpudLoader auth listening on ${port}`));
