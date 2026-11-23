// Offline TLS fixture. Its public test key and trust anchor never belong in the installed package.
import { appendFileSync, readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { observeExit } from './cloudflare-exit-probe.mjs';

const ca = readFileSync(new URL('./exit-observer-fixture-cert.pem', import.meta.url));
const key = readFileSync(new URL('./exit-observer-fixture-key.pem', import.meta.url));
const tlsContext = tls.createSecureContext({ key, cert: ca, minVersion: 'TLSv1.2' });
const loopback = '127.0.0.1';
const modes = new Set(['match', 'mismatch', 'timeout', 'invalid', 'reject', 'reset']);

const destinations = new Map([
  ['1.1.1.1:443', { key: 'cloudflare', id: 'CloudflareTrace', host: '1.1.1.1', path: '/cdn-cgi/trace' }],
  ['api.ipify.org:443', { key: 'ipify', id: 'Ipify', host: 'api.ipify.org', path: '/' }]
]);

function sendHttp(socket, status, body) {
  socket.end(`HTTP/1.1 ${status}\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
}

export async function startExitFixture(port, readControl) {
  const requests = [];
  const sockets = new Set();
  const server = http.createServer((_request, response) => {
    response.writeHead(405, { Connection: 'close' }).end();
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('connect', (request, socket, head) => {
    socket.on('error', () => {});
    const provider = destinations.get(request.url);
    if (!provider || request.headers.host !== request.url || head.length) {
      sendHttp(socket, '403 Forbidden', '');
      return;
    }
    let mode, address;
    try {
      const control = readControl(provider.id);
      mode = control[provider.key];
      address = mode === 'mismatch' ? control.otherIpv4 : control.expectedIpv4;
      if (!modes.has(mode) || !net.isIPv4(address)) throw new Error('Invalid fixture control');
    } catch {
      sendHttp(socket, '503 Unavailable', '');
      return;
    }
    requests.push(provider.id);
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (mode === 'reset') {
      socket.end();
      return;
    }

    const tunnel = new tls.TLSSocket(socket, { isServer: true, secureContext: tlsContext, ALPNProtocols: ['http/1.1'] });
    tunnel.on('error', () => tunnel.destroy());
    let headers = '';
    tunnel.on('data', chunk => {
      headers += chunk.toString('ascii');
      if (headers.length > 8192) return tunnel.destroy();
      if (!headers.endsWith('\r\n\r\n')) return;
      if (!headers.startsWith(`GET ${provider.path} HTTP/1.1\r\n`) ||
          !headers.toLowerCase().includes(`\r\nhost: ${provider.host}\r\n`) ||
          (provider.key === 'ipify' && tunnel.servername !== provider.host)) {
        return sendHttp(tunnel, '400 Bad Request', '');
      }
      if (mode === 'timeout') return;
      const body = mode === 'invalid' ? '2001:db8::1\n' :
        provider.key === 'cloudflare' ? `ip=${address}\n` : `${address}\n`;
      sendHttp(tunnel, mode === 'reject' ? '503 Unavailable' : '200 OK', body);
    });
  });
  server.listen(port, loopback);
  await once(server, 'listening');
  return {
    port: server.address().port,
    requests,
    async stop() {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    }
  };
}

export function observeFixture(input) {
  return observeExit(input, { ca });
}

function echo(port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: loopback, port, family: 4 });
    socket.setTimeout(1500, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.once('connect', () => socket.write(Buffer.from([0x53])));
    socket.once('data', data => { socket.destroy(); resolve(data.length === 1 && data[0] === 0x53); });
    socket.once('close', () => resolve(false));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, portArgument, controlArgument] = process.argv.slice(2);
  const port = Number(portArgument);
  if (action === 'observe') {
    const input = JSON.parse(readFileSync(0, 'utf8').replace(/^\uFEFF/, ''));
    const sample = await observeFixture(input);
    console.log(JSON.stringify(sample));
    if (!sample.Ok) process.exitCode = 1;
  } else if (action === 'echo' && Number.isInteger(port) && port > 1023 && port < 49152) {
    if (!(await echo(port))) process.exitCode = 1;
  } else if (action === 'serve' && Number.isInteger(port) && port > 1023 && port < 49152 && controlArgument) {
    const controlFile = resolve(controlArgument);
    const fixture = await startExitFixture(port, provider => {
      const control = JSON.parse(readFileSync(controlFile, 'utf8').replace(/^\uFEFF/, ''));
      if (control.receiptPath) {
        const receiptFile = resolve(dirname(controlFile), control.receiptPath);
        if (dirname(receiptFile) !== dirname(controlFile) || receiptFile === controlFile) {
          throw new Error('Fixture receipt must be beside the control file');
        }
        appendFileSync(receiptFile, provider + '\n');
      }
      return control;
    });
    console.log('READY ' + fixture.port);
  } else {
    throw new Error('Use serve <port> <control.json>, observe, or echo <port>');
  }
}
