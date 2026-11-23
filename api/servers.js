// Nugget Craft server list API (Vercel function).
// GET  /api/servers          -> { url, sealed, servers }  sealed = Neon Realtime live query of public servers
// GET  /api/servers?ip=X     -> { server }                look up one online server by IP (public or private)
// POST /api/servers {action:'create'|'beat'|'close', ...}
// POST /api/servers {action:'whoami'|'pin'|'unpin', ip}  with "Authorization: Bearer <NuggetAuth token>" (pin/unpin: admins only)
import { neon } from '@neondatabase/serverless';
import { createRealtime, rawSql } from '@neon/realtime/server';
import { createHash, randomBytes, randomInt } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const realtime = createRealtime({ secret: process.env.NEON_REALTIME_SECRET, db: 'neondb' });

const LIST_SQL = 'SELECT s.ip, s.name, s.motd, s.host_name, s.players, s.max_players, s.mods, s.last_seen, (p.ip IS NOT NULL) AS pinned FROM servers s LEFT JOIN pins p ON p.ip = s.ip WHERE s.is_public = true ORDER BY (p.ip IS NOT NULL) DESC, s.players DESC, s.ip LIMIT 60';
const NUGGETAUTH = 'https://nuggetauth.vercel.app';
const ADMINS = (process.env.NUGGETCRAFT_ADMINS || 'nugget').toLowerCase().split(',').map(x => x.trim()).filter(Boolean);
const MAX_SERVERS = 300;
// A server address: a number IP like 84.21.9.130 or a custom one like play.nugget (2-5 parts, letters/digits/dashes).
const IP_RE = /^(?=.{3,40}$)[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?){1,4}$/;
const MOD_IDS = ['lifesteal', 'shop', 'keepinv', 'nopvp', 'peaceful', 'day', 'kit', 'fastmine', 'notnt'];
const addr = v => clean(v, 40).toLowerCase();

const hash = t => createHash('sha256').update(String(t)).digest('hex');
const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n);
const int = (v, lo, hi, d) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d; };
// Who is signed in with Nugget (checked with NuggetAuth itself, never trusted from the browser).
async function nuggetUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!/^nat_[A-Za-z0-9_-]{20,80}$/.test(token)) return null;
  try {
    const r = await fetch(NUGGETAUTH + '/api/userinfo', { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) return null;
    const { user } = await r.json();
    return user && typeof user.username === 'string' ? user : null;
  } catch { return null; }
}
const isAdmin = u => !!u && u.type === 'nugget' && ADMINS.includes(u.username.toLowerCase());
const newIp = () => [randomInt(11, 224), randomInt(0, 256), randomInt(0, 256), randomInt(1, 255)].join('.');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    // Servers that stopped sending heartbeats disappear after 90 seconds.
    await sql`DELETE FROM servers WHERE last_seen < now() - interval '90 seconds'`;

    if (req.method === 'GET') {
      const ip = addr(req.query && req.query.ip);
      if (ip) {
        if (!IP_RE.test(ip)) return res.status(400).json({ error: 'That does not look like a server IP' });
        const rows = await sql`SELECT ip, name, motd, host_name, players, max_players, seed, mods FROM servers WHERE ip = ${ip}`;
        if (!rows.length) return res.status(404).json({ error: 'No server is online at that IP' });
        return res.status(200).json({ server: rows[0] });
      }
      const [servers, sealed] = await Promise.all([sql.query(LIST_SQL), realtime.seal({ query: rawSql(LIST_SQL) })]);
      return res.status(200).json({ url: process.env.NEON_REALTIME_URL, sealed, servers });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    let b = req.body;
    if (typeof b === 'string') { try { b = JSON.parse(b); } catch { b = {}; } }
    if (!b || typeof b !== 'object') b = {};

    if (b.action === 'whoami' || b.action === 'pin' || b.action === 'unpin') {
      const user = await nuggetUser(req);
      if (b.action === 'whoami') return res.status(200).json({ username: user ? user.username : null, admin: isAdmin(user) });
      if (!isAdmin(user)) return res.status(403).json({ error: 'Only admins can pin servers' });
      const ip = addr(b.ip);
      if (!IP_RE.test(ip)) return res.status(400).json({ error: 'Bad server IP' });
      if (b.action === 'pin') await sql`INSERT INTO pins (ip, pinned_by) VALUES (${ip}, ${user.username}) ON CONFLICT (ip) DO NOTHING`;
      else await sql`DELETE FROM pins WHERE ip = ${ip}`;
      return res.status(200).json({ ok: true, pinned: b.action === 'pin' });
    }

    if (b.action === 'create') {
      const [{ n }] = await sql`SELECT count(*)::int AS n FROM servers`;
      if (n >= MAX_SERVERS) return res.status(503).json({ error: 'Too many servers are online right now, try again soon' });
      const name = clean(b.name, 32) || 'Nugget Craft Server';
      const motd = clean(b.motd, 60);
      const host = clean(b.host, 16) || 'Player';
      const max = int(b.max, 2, 20, 10);
      const seed = int(b.seed, -2147483648, 2147483647, 0);
      const pub = b.public !== false;
      const mods = (Array.isArray(b.mods) ? b.mods : []).filter(m => MOD_IDS.includes(m)).filter((m, i, a) => a.indexOf(m) === i).join(',');
      // A host who hosted before keeps the same IP (so pins and friends' saved IPs keep working).
      let ip = null, token = null;
      const oldIp = addr(b.ip), oldToken = clean(b.token, 64), custom = addr(b.custom);
      if (custom) {
        // Custom address: free ones get reserved for this host, taken ones only work with the owner's token.
        if (!IP_RE.test(custom)) return res.status(400).json({ error: 'Custom IP can use letters, numbers, dashes and dots, like play.nugget or 12.34.56.78' });
        const [taken] = await sql`SELECT token_hash FROM server_ips WHERE ip = ${custom}`;
        if (taken) {
          if (!oldToken || taken.token_hash !== hash(oldToken)) return res.status(409).json({ error: `The IP ${custom} is already taken, pick another one` });
          ip = custom; token = oldToken;
        } else {
          token = oldToken || randomBytes(18).toString('hex');
          const rows = await sql`INSERT INTO server_ips (ip, token_hash) VALUES (${custom}, ${hash(token)}) ON CONFLICT (ip) DO NOTHING RETURNING ip`;
          if (!rows.length) return res.status(409).json({ error: `The IP ${custom} is already taken, pick another one` });
          ip = custom;
        }
      }
      if (!ip && IP_RE.test(oldIp) && oldToken) {
        const own = await sql`SELECT ip FROM server_ips WHERE ip = ${oldIp} AND token_hash = ${hash(oldToken)}`;
        if (own.length) { ip = oldIp; token = oldToken; }
      }
      if (!ip) {
        token = randomBytes(18).toString('hex');
        for (let tries = 0; tries < 8 && !ip; tries++) {
          const cand = newIp();
          const rows = await sql`INSERT INTO server_ips (ip, token_hash) VALUES (${cand}, ${hash(token)}) ON CONFLICT (ip) DO NOTHING RETURNING ip`;
          if (rows.length) ip = cand;
        }
        if (!ip) return res.status(500).json({ error: 'Could not pick a free IP, try again' });
      }
      await sql`INSERT INTO servers (ip, name, motd, host_name, players, max_players, seed, is_public, token_hash, mods)
        VALUES (${ip}, ${name}, ${motd}, ${host}, 1, ${max}, ${seed}, ${pub}, ${hash(token)}, ${mods})
        ON CONFLICT (ip) DO UPDATE SET name = EXCLUDED.name, motd = EXCLUDED.motd, host_name = EXCLUDED.host_name, players = 1,
          max_players = EXCLUDED.max_players, seed = EXCLUDED.seed, is_public = EXCLUDED.is_public, token_hash = EXCLUDED.token_hash,
          mods = EXCLUDED.mods, last_seen = now()`;
      return res.status(200).json({ ip, token });
    }

    const ip = addr(b.ip), token = clean(b.token, 64);
    if (!IP_RE.test(ip) || !token) return res.status(400).json({ error: 'Missing server IP or token' });

    if (b.action === 'beat') {
      const players = int(b.players, 0, 20, 1);
      const rows = await sql`UPDATE servers SET last_seen = now(), players = LEAST(${players}, max_players)
        WHERE ip = ${ip} AND token_hash = ${hash(token)} RETURNING ip`;
      if (!rows.length) return res.status(404).json({ error: 'Server not found' });
      return res.status(200).json({ ok: true });
    }
    if (b.action === 'close') {
      await sql`DELETE FROM servers WHERE ip = ${ip} AND token_hash = ${hash(token)}`;
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: 'Unknown action' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server list is having trouble, try again' });
  }
}
