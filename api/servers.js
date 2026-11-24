// Nugget Craft server list API (Vercel function).
// GET  /api/servers          -> { url, sealed, servers }  sealed = Neon Realtime live query of public servers
// GET  /api/servers?ip=X     -> { server }                look up one online server by IP (public or private)
// POST /api/servers {action:'create'|'beat'|'close', ...}
// GET  /api/servers?badge=X | ?cmd=X   -> check an admin badge / signed admin command
// POST /api/servers {action:'whoami'|'pin'|'unpin'|'remove'|'badge'|'sign', ...}  with "Authorization: Bearer <NuggetAuth token>" (pin/unpin: admins only)
import { neon } from '@neondatabase/serverless';
import { createRealtime, rawSql } from '@neon/realtime/server';
import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const realtime = createRealtime({ secret: process.env.NEON_REALTIME_SECRET, db: 'neondb' });

const LIST_SQL = 'SELECT s.ip, s.name, s.motd, s.host_name, s.players, s.max_players, s.mods, s.last_seen, (p.ip IS NOT NULL) AS pinned FROM servers s LEFT JOIN pins p ON p.ip = s.ip WHERE s.is_public = true ORDER BY (p.ip IS NOT NULL) DESC, s.last_seen DESC, s.ip LIMIT 60';
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
// Signed admin badges and one-minute admin commands, so other players can trust them without seeing anyone's sign-in.
const signKey = () => createHash('sha256').update('nuggetcraft-admin:' + (process.env.DATABASE_URL || '')).digest();
const sign = payload => createHmac('sha256', signKey()).update(payload).digest('base64url');
const pack = data => { const p = Buffer.from(JSON.stringify(data)).toString('base64url'); return p + '.' + sign(p); };
function unpack(tok) {
  const [p, sig] = String(tok || '').split('.');
  if (!p || !sig || p.length > 1500) return null;
  const want = Buffer.from(sign(p)), got = Buffer.from(sig);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d && d.e > Date.now() ? d : null; } catch { return null; }
}
const CMDS = ['kick', 'bring', 'heal', 'hearts', 'announce', 'time', 'freeze', 'setspawn', 'kill', 'clear', 'feed', 'gamemode'];
const isAdmin = u => !!u && u.type === 'nugget' && ADMINS.includes(u.username.toLowerCase());
const newIp = () => [randomInt(11, 224), randomInt(0, 256), randomInt(0, 256), randomInt(1, 255)].join('.');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    // Servers stay listed (online or offline); ones nobody has played for 30 days are cleaned up.
    await sql`DELETE FROM servers WHERE last_seen < now() - interval '30 days'`;

    if (req.method === 'GET') {
      const q = req.query || {};
      if (q.badge) { const d = unpack(q.badge); return res.status(200).json(d && d.t === 'badge' ? { ok: true, username: d.u, pid: d.pid } : { ok: false }); }
      if (q.world) { const ip = addr(q.world); const rows = await sql`SELECT data, chests, updated_at FROM server_worlds WHERE ip = ${ip}`; return res.status(200).json(rows.length ? { e3: rows[0].data, ch: rows[0].chests, updated_at: rows[0].updated_at } : { e3: null }); }
      if (q.cmd) { const d = unpack(q.cmd); return res.status(200).json(d && d.t === 'cmd' ? { ok: true, username: d.u, cmd: d.cmd, n: d.n } : { ok: false }); }
      const ip = addr(q.ip);
      if (ip) {
        if (!IP_RE.test(ip)) return res.status(400).json({ error: 'That does not look like a server IP' });
        const rows = await sql`SELECT ip, name, motd, host_name, players, max_players, seed, mods, last_seen FROM servers WHERE ip = ${ip}`;
        if (!rows.length) return res.status(404).json({ error: 'There is no server at that IP' });
        return res.status(200).json({ server: rows[0] });
      }
      const [servers, sealed] = await Promise.all([sql.query(LIST_SQL), realtime.seal({ query: rawSql(LIST_SQL) })]);
      return res.status(200).json({ url: process.env.NEON_REALTIME_URL, sealed, servers });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    let b = req.body;
    if (typeof b === 'string') { try { b = JSON.parse(b); } catch { b = {}; } }
    if (!b || typeof b !== 'object') b = {};

    if (['whoami', 'pin', 'unpin', 'remove', 'badge', 'sign'].includes(b.action)) {
      const user = await nuggetUser(req);
      if (b.action === 'whoami') return res.status(200).json({ username: user ? user.username : null, admin: isAdmin(user) });
      if (!isAdmin(user)) return res.status(403).json({ error: 'Only admins can do that' });
      if (b.action === 'badge') {
        const pid = clean(b.pid, 20);
        if (!pid) return res.status(400).json({ error: 'Missing player id' });
        return res.status(200).json({ badge: pack({ t: 'badge', u: user.username, pid, e: Date.now() + 12 * 3600e3 }) });
      }
      if (b.action === 'sign') {
        const c = b.cmd || {};
        if (!CMDS.includes(c.c)) return res.status(400).json({ error: 'Unknown admin command' });
        const cmd = { c: c.c, to: clean(c.to, 20) || 'all', room: clean(c.room, 60), text: clean(c.text, 120), a: Array.isArray(c.a) ? c.a.slice(0, 3).map(Number).filter(Number.isFinite) : [] };
        return res.status(200).json({ signed: pack({ t: 'cmd', u: user.username, cmd, n: randomBytes(8).toString('hex'), e: Date.now() + 60e3 }) });
      }
      if (b.action === 'remove') {
        const ip = addr(b.ip);
        await sql`DELETE FROM servers WHERE ip = ${ip}`;
        await sql`DELETE FROM server_worlds WHERE ip = ${ip}`;
        return res.status(200).json({ ok: true });
      }
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
      const max = int(b.max, 2, 50, 10);
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

    // Anyone playing on a server keeps it marked online, and saves its world so it carries on when the host is away.
    if (b.action === 'ping' || b.action === 'saveworld') {
      const ip = addr(b.ip);
      if (!IP_RE.test(ip)) return res.status(400).json({ error: 'Bad server IP' });
      const [sv] = await sql`SELECT ip FROM servers WHERE ip = ${ip}`;
      if (!sv) return res.status(404).json({ error: 'Server not found' });
      if (b.action === 'ping') {
        await sql`UPDATE servers SET last_seen = now(), players = LEAST(${int(b.players, 0, 50, 1)}, max_players) WHERE ip = ${ip}`;
        return res.status(200).json({ ok: true });
      }
      const data = typeof b.e3 === 'string' ? b.e3 : '';
      if (data.length > 3500000 || !/^[A-Za-z0-9+/=]*$/.test(data)) return res.status(413).json({ error: 'World is too big to save online' });
      const ch = typeof b.ch === 'string' && b.ch.length < 500000 ? b.ch : '[]';
      await sql`INSERT INTO server_worlds (ip, data, chests, updated_at) VALUES (${ip}, ${data}, ${ch}, now()) ON CONFLICT (ip) DO UPDATE SET data = EXCLUDED.data, chests = EXCLUDED.chests, updated_at = now()`;
      return res.status(200).json({ ok: true });
    }

    const ip = addr(b.ip), token = clean(b.token, 64);
    if (!IP_RE.test(ip) || !token) return res.status(400).json({ error: 'Missing server IP or token' });

    if (b.action === 'beat') {
      const players = int(b.players, 0, 50, 1);
      const rows = await sql`UPDATE servers SET last_seen = now(), players = LEAST(${players}, max_players)
        WHERE ip = ${ip} AND token_hash = ${hash(token)} RETURNING ip`;
      if (!rows.length) return res.status(404).json({ error: 'Server not found' });
      return res.status(200).json({ ok: true });
    }
    if (b.action === 'close') {
      const gone = await sql`DELETE FROM servers WHERE ip = ${ip} AND token_hash = ${hash(token)} RETURNING ip`;
      if (gone.length) await sql`DELETE FROM server_worlds WHERE ip = ${ip}`;
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: 'Unknown action' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server list is having trouble, try again' });
  }
}
