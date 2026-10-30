#!/usr/bin/env node
/**
 * Pure-Node VLESS + WebSocket server for Pxxl App (app.pxxl.app) Free.
 *
 * Pxxl's edge terminates TLS on <name>.pxxlspace.cv:443 and forwards plain
 * HTTP/WS to the container on $PORT. The client therefore uses
 * security=tls + type=ws; inside the container this process only speaks WS.
 *
 * Env:
 *   PORT | SERVER_PORT   listen port (Pxxl injects PORT)
 *   UUID | APP_KEY       VLESS id (required; aliases accepted)
 *   WSPATH | API_ROUTE   WebSocket path (must start with /)
 *   PUBLIC_HOST          your <name>.pxxlspace.cv host (for the printed link)
 *   EDGE_TLS=1           print a security=tls link on port 443
 *   NODE_NAME            link fragment (default Pxxl-WS)
 *   PRINT_LINK=0         do not print the client link/subscription
 *
 * Limit: TCP only (command 1). UDP (command 2) and Mux (command 3) are
 * rejected; standard browser traffic is TCP. TLS is provided by Pxxl's edge;
 * the container-to-edge hop is plain WS.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');

const HERE = __dirname;
const TAG = '[vless-ws]';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME = 16 * 1024 * 1024;
const MAX_CONN = 128;
const HANDSHAKE_TIMEOUT = Number(process.env.HANDSHAKE_TIMEOUT_MS || 30000);

const PORT = Number(process.env.PORT || process.env.SERVER_PORT || 0);
const RAW_PATH =
  process.env.WSPATH || process.env.API_ROUTE || process.env.WS_PATH || '/api/v1/sync';
const WS_PATH = '/' + String(RAW_PATH).replace(/^\/+/, '');
const NODE_NAME = process.env.NODE_NAME || 'Pxxl-WS';
const EDGE_TLS = process.env.EDGE_TLS === '1' || process.env.TLS === '1';
const UUID_FILE = process.env.UUID_FILE || path.join(HERE, '.uuid');

function log(msg) {
  console.log(`${TAG} ${msg}`);
}
function warn(msg) {
  console.error(`${TAG} WARN: ${msg}`);
}
function die(msg) {
  console.error(`${TAG} FATAL: ${msg}`);
  process.exit(1);
}

/* ------------------------------------------------------------------ UUID */

function isUuid(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function resolveUuid() {
  const fromEnv = (process.env.UUID || process.env.APP_KEY || '').trim();
  if (fromEnv) {
    if (!isUuid(fromEnv) && process.env.UUID_ALLOW_ANY !== '1') {
      die(`UUID is not a valid UUID (got "${fromEnv.slice(0, 8)}…")`);
    }
    return fromEnv;
  }
  try {
    const saved = fs.readFileSync(UUID_FILE, 'utf8').trim();
    if (isUuid(saved)) {
      log(`using UUID persisted in ${path.basename(UUID_FILE)}`);
      return saved;
    }
  } catch (_) {}
  const generated = crypto.randomUUID();
  try {
    fs.writeFileSync(UUID_FILE, generated + '\n', { mode: 0o600 });
    warn('no UUID env; generated one into .uuid (set env UUID to pin it)');
  } catch (e) {
    warn(`could not persist UUID: ${e.message}`);
  }
  return generated;
}

const UUID = resolveUuid();
const UUID_BYTES = Buffer.from(UUID.replace(/-/g, ''), 'hex');

/* --------------------------------------------------------------- websocket */

class WebSocket {
  constructor(socket, head) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.frag = null;
    this.fragLen = 0;
    this.closed = false;
    this.finished = false;
    this._onMessage = null;
    this.pending = [];
    this.onClose = null;

    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.on('data', (d) => {
      try {
        this._feed(d);
      } catch (e) {
        log(`ws protocol error: ${e.message}`);
        this.close(1002);
      }
    });
    socket.on('error', () => this._finish());
    socket.on('close', () => this._finish());

    if (head && head.length) {
      try {
        this._feed(head);
      } catch (e) {
        log(`ws protocol error: ${e.message}`);
        this.close(1002);
      }
    }

    // A client may reset right after the 101. The 'close' event can already
    // have fired before the listener above was attached, so finish explicitly.
    queueMicrotask(() => {
      if (socket.destroyed) this._finish();
    });
  }

  _feed(data) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, data]) : data;
    for (;;) {
      const f = this._parse();
      if (!f) return;
      this._handle(f);
      if (this.closed) return;
    }
  }

  _parse() {
    const b = this.buf;
    if (b.length < 2) return null;
    if (b[0] & 0x70) throw new Error('RSV bits are set');
    const fin = Boolean(b[0] & 0x80);
    const opcode = b[0] & 0x0f;
    const masked = Boolean(b[1] & 0x80);
    let len = b[1] & 0x7f;
    let off = 2;

    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      if (b.readUInt32BE(2) !== 0) throw new Error('frame too large');
      len = b.readUInt32BE(6);
      off = 10;
    }
    if (len > MAX_FRAME) throw new Error('frame too large');
    if (!masked) throw new Error('client frame is not masked');
    if (b.length < off + 4 + len) return null;

    const mask = b.subarray(off, off + 4);
    off += 4;
    // In-place unmask: the received chunk belongs to this socket, and the
    // payload is forwarded immediately. Avoids a full copy per frame.
    const payload = b.subarray(off, off + len);
    for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
    this.buf = b.subarray(off + len);
    return { fin, opcode, payload };
  }

  _handle(f) {
    const control = f.opcode >= 0x8;
    if (control && (!f.fin || f.payload.length > 125)) {
      this.close(1002);
      return;
    }
    switch (f.opcode) {
      case 0x0: // continuation
      case 0x2: // binary
        if (f.opcode === 0x2 && this.frag) {
          this.close(1002);
          return;
        }
        if (!this.frag) {
          this.frag = [];
          this.fragLen = 0;
        }
        this.frag.push(f.payload);
        this.fragLen += f.payload.length;
        if (this.fragLen > MAX_FRAME) {
          this.frag = null;
          this.fragLen = 0;
          this.close(1009);
          return;
        }
        if (f.fin) {
          const msg = Buffer.concat(this.frag);
          this.frag = null;
          this.fragLen = 0;
          if (this._onMessage) this._onMessage(msg);
          else this.pending.push(msg); // head may already hold a full frame
        }
        break;
      case 0x1: // text: VLESS is binary
        this.close(1003);
        break;
      case 0x8: // close
        this.close(1000);
        break;
      case 0x9: // ping
        this._send(0xa, f.payload);
        break;
      case 0xa: // pong
        break;
      default:
        this.close(1002);
    }
  }

  _send(opcode, payload) {
    if (this.socket.destroyed) return false;
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 127;
      header.writeUInt32BE(0, 2);
      header.writeUInt32BE(len, 6);
    }
    header[0] = 0x80 | opcode;
    try {
      // cork + two writes becomes one writev, avoiding a header+payload copy
      // on every frame (the hot path when a client downloads).
      this.socket.cork();
      let ok = this.socket.write(header);
      if (payload.length) ok = this.socket.write(payload) && ok;
      this.socket.uncork();
      return ok;
    } catch (_) {
      try {
        this.socket.uncork();
      } catch (_) {}
      return false;
    }
  }

  sendBinary(payload) {
    return this._send(0x2, payload);
  }

  setMessageHandler(fn) {
    this._onMessage = fn;
    if (!this.pending.length) return;
    const queued = this.pending;
    this.pending = [];
    for (const m of queued) fn(m);
  }

  close(code = 1000) {
    if (this.closed) return;
    this.closed = true;
    const p = Buffer.alloc(2);
    p.writeUInt16BE(code, 0);
    this._send(0x8, p);
    try {
      this.socket.end();
    } catch (_) {}
    setTimeout(() => {
      try {
        this.socket.destroy();
      } catch (_) {}
    }, 2000).unref?.();
  }

  _finish() {
    if (this.finished) return;
    this.finished = true;
    this.closed = true;
    try {
      this.socket.destroy();
    } catch (_) {}
    if (this.onClose) this.onClose();
  }
}

/* ------------------------------------------------------------------ vless */

class Session {
  constructor(ws, onDone) {
    this.ws = ws;
    this.buf = Buffer.alloc(0);
    this.headerDone = false;
    this.target = null;
    this.closed = false;
    this.done = false;
    this.onDone = onDone;
    this.handshakeTimer = setTimeout(() => {
      if (this.headerDone || this.closed) return;
      log('handshake timeout (no VLESS header)');
      this.ws.close(1008);
      this.destroy();
    }, HANDSHAKE_TIMEOUT);
    this.handshakeTimer.unref?.();

    ws.setMessageHandler((m) => this.onData(m));
    ws.onClose = () => {
      clearTimeout(this.handshakeTimer);
      this.destroy();
      if (!this.done) {
        this.done = true;
        if (this.onDone) this.onDone();
      }
    };
  }

  onData(chunk) {
    if (this.closed) return;
    if (this.headerDone) {
      this.toTarget(chunk);
      return;
    }
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const req = this.parseHeader();
    if (!req) return;
    if (req.error) {
      log(`reject: ${req.error}`);
      this.ws.close(1008);
      return;
    }
    this.headerDone = true;
    clearTimeout(this.handshakeTimer);
    const rest = this.buf.subarray(req.consumed);
    this.buf = Buffer.alloc(0);
    this.connect(req, rest);
  }

  parseHeader() {
    const b = this.buf;
    if (b.length < 18) return null;
    if (b[0] !== 0) return { error: `bad version ${b[0]}` };

    const id = b.subarray(1, 17);
    if (!crypto.timingSafeEqual(id, UUID_BYTES)) return { error: 'bad uuid' };

    const addonLen = b[17];
    const base = 18 + addonLen;
    if (b.length < base + 4) return null;

    const cmd = b[base];
    const port = b.readUInt16BE(base + 1);
    const atyp = b[base + 3];
    let p = base + 4;
    let host;

    if (atyp === 1) {
      if (b.length < p + 4) return null;
      host = `${b[p]}.${b[p + 1]}.${b[p + 2]}.${b[p + 3]}`;
      p += 4;
    } else if (atyp === 2) {
      if (b.length < p + 1) return null;
      const n = b[p];
      p += 1;
      if (b.length < p + n) return null;
      host = b.toString('utf8', p, p + n);
      p += n;
    } else if (atyp === 3) {
      if (b.length < p + 16) return null;
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(p + i).toString(16));
      host = parts.join(':');
      p += 16;
    } else {
      return { error: `bad address type ${atyp}` };
    }

    return { cmd, host, port, consumed: p };
  }

  connect(req, rest) {
    if (req.cmd !== 1) {
      log(`reject: command ${req.cmd} (UDP/Mux not supported)`);
      this.ws.close(1003);
      return;
    }
    if (!req.host || !req.port) {
      this.ws.close(1008);
      return;
    }

    const target = net.connect({ host: req.host, port: req.port });
    this.target = target;
    target.setNoDelay(true);

    const timer = setTimeout(() => {
      log(`connect timeout ${req.host}:${req.port}`);
      target.destroy();
    }, 15000);

    target.on('connect', () => {
      clearTimeout(timer);
      if (this.closed) {
        target.destroy();
        return;
      }
      log(`connect ${req.host}:${req.port}`);
      // VLESS response: version 0, addon length 0, then payload.
      this.ws.sendBinary(Buffer.from([0, 0]));
      if (rest.length) this.toTarget(rest);
      target.on('data', (d) => {
        if (!this.ws.sendBinary(d)) {
          target.pause();
          this.ws.socket.once('drain', () => target.resume());
        }
      });
    });

    target.on('error', (e) => {
      clearTimeout(timer);
      log(`target error ${e.code || e.message}`);
      this.destroy();
    });
    target.on('close', () => this.destroy());
  }

  toTarget(data) {
    if (!this.target || this.target.destroyed) return;
    try {
      if (!this.target.write(data)) {
        this.ws.socket.pause();
        this.target.once('drain', () => this.ws.socket.resume());
      }
    } catch (e) {
      log(`target write error: ${e.code || e.message}`);
      this.destroy();
    }
  }

  destroy() {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.handshakeTimer);
    try {
      if (this.target) this.target.destroy();
    } catch (_) {}
    try {
      this.ws.close(1000);
    } catch (_) {}
  }
}

/* ------------------------------------------------------------- link output */

function httpGetText(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

async function detectPublicHost() {
  if (process.env.PUBLIC_HOST) return process.env.PUBLIC_HOST.trim();
  try {
    const text = await httpGetText('https://api.ipify.org', 5000);
    const ip = text.trim();
    if (/^[0-9a-f:.]+$/i.test(ip)) return ip;
  } catch (_) {}
  return 'YOUR_PANEL_IP';
}

async function printLink() {
  if (process.env.PRINT_LINK === '0') return;
  const host = await detectPublicHost();
  const linkPort = EDGE_TLS ? 443 : PORT;
  const params = {
    encryption: 'none',
    security: EDGE_TLS ? 'tls' : 'none',
    type: 'ws',
    host,
    path: WS_PATH,
  };
  if (EDGE_TLS) params.sni = host;
  const query = new URLSearchParams(params);
  const link = `vless://${UUID}@${host}:${linkPort}?${query.toString()}#${encodeURIComponent(NODE_NAME)}`;
  const sub = Buffer.from(link + '\n', 'utf8').toString('base64');
  log('client link:');
  console.log(link);
  log('base64 subscription:');
  console.log(sub);
  if (host === 'YOUR_PANEL_IP') {
    warn('could not detect public host; set PUBLIC_HOST=<name>.pxxlspace.cv');
  } else if (EDGE_TLS && /^[0-9a-f:.]+$/i.test(host)) {
    warn('EDGE_TLS is on but PUBLIC_HOST is an IP; set it to <name>.pxxlspace.cv');
  }
}

/* ------------------------------------------------------------------- main */

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  die(`invalid PORT/SERVER_PORT: ${process.env.PORT || process.env.SERVER_PORT || '(unset)'}`);
}

let active = 0;

function fdCount() {
  try {
    return fs.readdirSync('/proc/self/fd').length;
  } catch (_) {
    return -1;
  }
}

// Percentage of one CPU core, sampled between heartbeats. A free panel may
// stop a container whose CPU stays above ~15% for 5 minutes.
let cpuPct = 0;
let prevCpu = process.cpuUsage();
let prevCpuAt = Date.now();

function sampleCpu() {
  const now = process.cpuUsage();
  const at = Date.now();
  const used = now.user - prevCpu.user + (now.system - prevCpu.system);
  const elapsed = (at - prevCpuAt) * 1000;
  prevCpu = now;
  prevCpuAt = at;
  cpuPct = elapsed > 0 ? Math.round((used / elapsed) * 1000) / 10 : 0;
  return cpuPct;
}

function stats() {
  const m = process.memoryUsage();
  return {
    uptime: Math.round(process.uptime()),
    conns: active,
    cpuPct,
    rssMB: Math.round(m.rss / 1048576),
    heapMB: Math.round(m.heapUsed / 1048576),
    fds: fdCount(),
  };
}

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  if (url === '/__health') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: true, ...stats() }) + '\n');
    return;
  }
  log(`health ${req.method} ${url} ua=${req.headers['user-agent'] || '-'}`);
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('ok\n');
});

server.on('upgrade', (req, socket, head) => {
  // A reset between the 101 and the WebSocket listeners would otherwise be an
  // unhandled 'error' event and kill the process.
  socket.on('error', () => {});
  try {
    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch (_) {
      pathname = '';
    }
    if (pathname !== WS_PATH) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    const key = req.headers['sec-websocket-key'];
    const upgrade = String(req.headers.upgrade || '').toLowerCase();
    if (upgrade !== 'websocket' || !key) {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (active >= MAX_CONN) {
      warn(`connection limit reached (${active}); refusing upgrade`);
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    const accept = crypto
      .createHash('sha1')
      .update(key + WS_GUID)
      .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );

    active += 1;
    try {
      const ws = new WebSocket(socket, head);
      new Session(ws, () => {
        active = Math.max(0, active - 1);
      });
    } catch (e) {
      active = Math.max(0, active - 1);
      throw e;
    }
  } catch (e) {
    console.error(`${TAG} upgrade error: ${e.stack || e}`);
    try {
      socket.destroy();
    } catch (_) {}
  }
});

server.on('clientError', (_err, socket) => {
  try {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  } catch (_) {}
});

server.on('error', (e) => {
  console.error(`${TAG} server error: ${e.stack || e}`);
  process.exit(1);
});

process.on('uncaughtException', (e) => {
  console.error(`${TAG} UNCAUGHT: ${e.stack || e}`);
});
process.on('unhandledRejection', (e) => {
  console.error(`${TAG} UNHANDLED REJECTION: ${e && e.stack ? e.stack : e}`);
});
process.on('exit', (code) => {
  log(`exiting code=${code} uptime=${Math.round(process.uptime())}s ${JSON.stringify(stats())}`);
});

server.listen(PORT, '0.0.0.0', async () => {
  log(`listening on 0.0.0.0:${PORT} path ${WS_PATH} (pure Node VLESS/WS)`);
  // Pterodactyl eggs detect "startup done" by matching a console string. Print
  // the common variants so the panel leaves the Starting state instead of
  // treating a healthy listener as a failed boot.
  log('Server started');
  log(`Listening on 0.0.0.0:${PORT}`);
  log('Ready / ready / Done / done');
  log(`uuid ${UUID.slice(0, 8)}…${UUID.slice(-4)}`);
  await printLink();
});

const heartbeat = setInterval(() => {
  sampleCpu();
  const s = stats();
  log(
    `alive ${s.uptime}s conns=${s.conns} cpu=${s.cpuPct}% rss=${s.rssMB}MB heap=${s.heapMB}MB fds=${s.fds}`
  );
  if (s.cpuPct >= 15) {
    warn(`CPU ${s.cpuPct}% >= 15% — free panels often stop the server after 5 min above this`);
  }
}, 20000);
heartbeat.unref?.();

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    log(`received ${sig}, shutting down`);
    try {
      server.close();
    } catch (_) {}
    setTimeout(() => process.exit(0), 1500).unref?.();
  });
}
