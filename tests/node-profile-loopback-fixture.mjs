import { appendFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { observeFixture } from './exit-observer-fixture.mjs';

const expectedId = Buffer.from('00000000000040008000000000000009', 'hex');
const cloudflareAddress = Buffer.from([1, 1, 1, 1]);
const ipifyHost = Buffer.from('api.ipify.org');
const reply = Buffer.from([0, 0]);
const certificate = readFileSync(new URL('./exit-observer-fixture-cert.pem', import.meta.url));
const privateKey = readFileSync(new URL('./exit-observer-fixture-key.pem', import.meta.url));

function frame(opcode, payload) {
  if (payload.length < 126) return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
  const header = Buffer.from([0x80 | opcode, 126, 0, 0]);
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

function startWebSocketRelay(port, rawPort, receipt) {
  if (![port, rawPort].every(p => Number.isInteger(p) && p > 1023 && p < 49152) || port === rawPort) {
    throw new Error('Expected separate isolated WebSocket and fixture ports');
  }
  const context = tls.createSecureContext({ key: privateKey, cert: certificate, minVersion: 'TLSv1.2' });
  const server = https.createServer({ key: privateKey, cert: certificate, SNICallback(name, done) {
    if (name !== 'api.ipify.org') return done(new Error('Wrong synthetic SNI'));
    appendFileSync(receipt, 'PinnedWssSni\n');
    done(null, context);
  } });
  server.on('tlsClientError', () => {});
  server.on('upgrade', (request, socket, early) => {
    const key = request.headers['sec-websocket-key'];
    if (request.url !== '/guard/socket?mode=fixture' || request.headers.host !== 'edge.example.test' ||
        request.socket.servername !== 'api.ipify.org' || request.headers.upgrade?.toLowerCase() !== 'websocket' ||
        request.headers['sec-websocket-version'] !== '13' || !/^[A-Za-z0-9+/]{22}==$/.test(key ?? '')) {
      socket.destroy();
      return;
    }
    appendFileSync(receipt, 'PinnedWssUpgrade\n');
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const raw = net.createConnection({ host: '127.0.0.1', port: rawPort, family: 4 });
    let pending = Buffer.alloc(0);
    const stop = () => { socket.destroy(); raw.destroy(); };
    socket.on('error', stop).on('close', stop);
    raw.on('error', stop).on('close', stop);
    raw.on('data', chunk => {
      for (let offset = 0; offset < chunk.length; offset += 16384) socket.write(frame(2, chunk.subarray(offset, offset + 16384)));
    });
    const receive = chunk => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 2) {
        const opcode = pending[0] & 15;
        let size = pending[1] & 127;
        if ((pending[0] & 112) || !(pending[1] & 128) || size === 127) return stop();
        const start = size === 126 ? 4 : 2;
        if (pending.length < start + 4) return;
        if (start === 4) size = pending.readUInt16BE(2);
        const end = start + 4 + size;
        if (pending.length < end) return;
        const payload = Buffer.from(pending.subarray(start + 4, end));
        for (let offset = 0; offset < size; offset++) payload[offset] ^= pending[start + offset % 4];
        pending = pending.subarray(end);
        if (opcode === 8) return stop();
        if (opcode === 9) socket.write(frame(10, payload));
        else if (opcode === 2 || opcode === 0) raw.write(payload);
        else if (opcode !== 10) return stop();
      }
    };
    socket.on('data', receive);
    if (early.length) receive(early);
  });
  server.listen(port, '127.0.0.1');
}

if (process.argv[2] === 'serve-wss') {
  startWebSocketRelay(Number(process.argv[3]), Number(process.argv[4]), process.argv[5]);
} else if (process.argv[2] === 'serve') {
  const port = Number(process.argv[3]);
  const result = process.argv[4];
  const receipt = process.argv[5];
  if (!Number.isInteger(port) || port < 1024 || port > 49151 ||
      !['success', 'no-loc', 'duplicate-loc', 'invalid-loc', 'fallback', 'invalid', 'hold', 'untrusted-ws'].includes(result)) {
    throw new Error('Expected an isolated fixture port and mode');
  }
  const context = tls.createSecureContext({
    cert: certificate,
    key: privateKey,
    minVersion: 'TLSv1.2'
  });
  if (result === 'untrusted-ws') {
    const upstream = tls.createServer({
      SNICallback(name, done) {
        if (name === 'example.test') appendFileSync(receipt, 'PinnedWebSocketTlsAttempt\n');
        done(null, context);
      }
    }, socket => socket.destroy());
    upstream.on('tlsClientError', () => {});
    upstream.listen(port, '127.0.0.1');
  } else net.createServer(socket => {
    let preface = Buffer.alloc(0);
    socket.on('error', () => socket.destroy());
    const accept = chunk => {
      preface = Buffer.concat([preface, chunk]);
      if (preface.length < 22) return;
      if (preface[0] !== 0 || !preface.subarray(1, 17).equals(expectedId) || preface[17] !== 0 ||
          preface[18] !== 1 || preface.readUInt16BE(19) !== 443) {
        socket.destroy();
        return;
      }
      const backup = preface[21] === 2 && result === 'fallback';
      const headerLength = backup ? 23 + ipifyHost.length : 26;
      if (preface.length < headerLength) return;
      const expectedAddress = backup ? ipifyHost : cloudflareAddress;
      if ((backup ? preface[22] !== ipifyHost.length : preface[21] !== 1) ||
          !preface.subarray(backup ? 23 : 22, headerLength).equals(expectedAddress)) return socket.destroy();
      socket.pause();
      socket.off('data', accept);
      if (preface.length > headerLength) socket.unshift(preface.subarray(headerLength));
      socket.write(reply);
      const tunnel = new tls.TLSSocket(socket, { isServer: true, secureContext: context, ALPNProtocols: ['http/1.1'] });
      tunnel.on('error', () => tunnel.destroy());
      let request = '';
      tunnel.on('data', data => {
        request += data.toString('ascii');
        if (request.length > 4096) return tunnel.destroy();
        if (!request.endsWith('\r\n\r\n')) return;
        const host = backup ? 'api.ipify.org' : '1.1.1.1';
        const path = backup ? '/' : '/cdn-cgi/trace';
        if (!request.startsWith(`GET ${path} HTTP/1.1\r\n`) ||
            !request.toLowerCase().includes(`\r\nhost: ${host}\r\n`) ||
            (backup && tunnel.servername !== host)) return tunnel.destroy();
        appendFileSync(receipt, backup ? 'PinnedTlsRequest:Ipify\n' : 'PinnedTlsRequest:Cloudflare\n');
        if (result === 'hold') return;
        const location = { success: 'loc=JP\n', 'duplicate-loc': 'loc=JP\nloc=JP\n', 'invalid-loc': 'loc=XX\n' };
        const body = backup ? '203.0.113.52\n' :
          result === 'invalid' ? 'ip=not-an-ip\n' : `ip=203.0.113.51\n${location[result] ?? ''}`;
        const status = result === 'fallback' && !backup ? '503 Unavailable' : '200 OK';
        tunnel.end(`HTTP/1.1 ${status}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
      tunnel.resume();
    };
    socket.on('data', accept);
  }).listen(port, '127.0.0.1');
} else {
  // This test trust anchor is never used by the installed public observer.
  const input = JSON.parse(readFileSync(0, 'utf8').replace(/^\uFEFF/, ''));
  const result = await observeFixture(input);
  console.log(JSON.stringify(result));
  if (!result.Ok) process.exitCode = 1;
}
