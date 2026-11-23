// Nugget Craft server list API (Vercel function).
// GET  /api/servers          -> { url, sealed, servers }  sealed = Neon Realtime live query of public servers
// GET  /api/servers?ip=X     -> { server }                look up one online server by IP (public or private)
// POST /api/servers {action:'create'|'beat'|'close', ...}
import { neon } from '@neondatabase/serverless';
import { createRealtime, rawSql } from '@neon/realtime/server';
import { createHash, randomBytes, randomInt } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const realtime = createRealtime({ secret: process.env.NEON_REALTIME_SECRET, db: 'neondb' });

const LIST_SQL = 'SELECT ip, name, motd, host_name, players, max_players, last_seen FROM servers WHERE is_public = true ORDER BY players DESC, ip LIMIT 60';
const MAX_SERVERS = 300;
const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const hash = t => createHash('sha256').update(String(t)).digest('hex');
const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n);
const int = (v, lo, hi, d) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d; };
const newIp = () => [randomInt(11, 224), randomInt(0, 256), randomInt(0, 256), randomInt(1, 255)].join('.');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    // Servers that stopped sending heartbeats disappear after 90 seconds.
    await sql`DELETE FROM servers WHERE last_seen < now() - interval '90 seconds'`;

    if (req.method === 'GET') {
      const ip = clean(req.query && req.query.ip, 15);
      if (ip) {
        if (!IP_RE.test(ip)) return res.status(400).json({ error: 'That does not look like a server IP' });
        const rows = await sql`SELECT ip, name, motd, host_name, players, max_players, seed FROM servers WHERE ip = ${ip}`;
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

    if (b.action === 'create') {
      const [{ n }] = await sql`SELECT count(*)::int AS n FROM servers`;
      if (n >= MAX_SERVERS) return res.status(503).json({ error: 'Too many servers are online right now, try again soon' });
      const name = clean(b.name, 32) || 'Nugget Craft Server';
      const motd = clean(b.motd, 60);
      const host = clean(b.host, 16) || 'Player';
      const max = int(b.max, 2, 20, 10);
      const seed = int(b.seed, -2147483648, 2147483647, 0);
      const pub = b.public !== false;
      const token = randomBytes(18).toString('hex');
      for (let tries = 0; tries < 6; tries++) {
        const ip = newIp();
        const rows = await sql`INSERT INTO servers (ip, name, motd, host_name, players, max_players, seed, is_public, token_hash)
          VALUES (${ip}, ${name}, ${motd}, ${host}, 1, ${max}, ${seed}, ${pub}, ${hash(token)})
          ON CONFLICT (ip) DO NOTHING RETURNING ip`;
        if (rows.length) return res.status(200).json({ ip, token });
      }
      return res.status(500).json({ error: 'Could not pick a free IP, try again' });
    }

    const ip = clean(b.ip, 15), token = clean(b.token, 64);
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
