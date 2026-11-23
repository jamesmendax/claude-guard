import { readFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const limit = 8192;
const maxDeadlineMs = 14000;
// ISO 3166-1 alpha-2 assignments. Unknown and special-purpose values such as XX and T1 are not countries.
const countryCodes = new Set(`
  AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
  CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
  GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
  KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS
  MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
  SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
  UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
`.trim().split(/\s+/));
const cloudflare = Object.freeze({
  id: 'CloudflareTrace', host: '1.1.1.1', path: '/cdn-cgi/trace', parse: parseTrace
});
const ipify = Object.freeze({
  id: 'Ipify', host: 'api.ipify.org', path: '/', parse: parsePlainAddress
});

function openTunnel(port, provider, authorization, signal, onConnected) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port, family: 4, signal });
    let header = Buffer.alloc(0);
    const deadline = setTimeout(() => socket.destroy(new Error('ProxyConnectTimeout')), 7000);
    const fail = () => {
      clearTimeout(deadline);
      socket.destroy();
      reject(new Error('ProxyConnectRejected'));
    };
    const receive = (chunk) => {
      header = Buffer.concat([header, chunk]);
      if (header.length > limit) return fail();
      const end = header.indexOf('\r\n\r\n');
      if (end === -1) return;
      const reply = header.subarray(0, end).toString('ascii');
      if (!/^HTTP\/1\.[01] 200(?:[ \r]|$)/.test(reply)) return fail();
      clearTimeout(deadline);
      socket.pause();
      socket.removeListener('data', receive);
      if (end + 4 < header.length) socket.unshift(header.subarray(end + 4));
      resolve(socket);
    };
    socket.once('error', fail);
    socket.once('close', () => {
      clearTimeout(deadline);
      reject(new Error('ProxyClosed'));
    });
    socket.on('data', receive);
    socket.once('connect', () => {
      onConnected?.(socket.localPort, new Date().toISOString());
      const credential = authorization ? 'Proxy-Authorization: Basic ' + authorization + '\r\n' : '';
      socket.write(
        'CONNECT ' + provider.host + ':443 HTTP/1.1\r\n' +
        'Host: ' + provider.host + ':443\r\n' +
        credential + '\r\n'
      );
    });
  });
}

function parseTrace(body, headers, includeCountry) {
  const addresses = [...body.matchAll(/^ip=([^\r\n]+)\r?$/gm)];
  if (addresses.length !== 1 || !net.isIPv4(addresses[0][1])) {
    throw new Error('NoSingleIpv4InTrace');
  }
  const result = {
    Ipv4: addresses[0][1],
    CfRay: /^[a-f0-9]{8,32}(?:-[A-Z0-9]{2,6})?$/.test(headers['cf-ray'] ?? '') ? headers['cf-ray'] : null
  };
  if (includeCountry) {
    const locations = [...body.matchAll(/^loc=([^\r\n]*)\r?$/gm)];
    result.CountryCode = locations.length === 1 && countryCodes.has(locations[0][1]) ? locations[0][1] : null;
  }
  return result;
}

function parsePlainAddress(body) {
  const address = body.replace(/\r?\n$/, '');
  if (!net.isIPv4(address)) throw new Error('NoSingleIpv4');
  return { Ipv4: address };
}

function readAddress(socket, provider, signal, includeCountry) {
  if (!socket.authorized) throw new Error('ProviderTlsUnverified');
  const agent = new http.Agent({ keepAlive: false });
  let used = false;
  agent.createConnection = () => {
    if (used) throw new Error('OnlyOneSocketAllowed');
    used = true;
    return socket;
  };
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: provider.host,
      port: 443,
      path: provider.path,
      method: 'GET',
      headers: { Host: provider.host, Accept: 'text/plain', 'Cache-Control': 'no-cache', Connection: 'close' },
      agent,
      signal
    }, (response) => {
      if (response.statusCode !== 200) {
        response.destroy();
        return reject(new Error('ProviderResponseRejected'));
      }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > limit) {
          response.destroy(new Error('TraceTooLarge'));
        }
      });
      response.on('error', reject);
      response.once('end', () => {
        try {
          resolve({ HttpStatus: response.statusCode, ...provider.parse(body, response.headers, includeCountry) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.once('error', reject);
    request.setTimeout(7500, () => request.destroy(new Error('ProviderTimeout')));
    request.end();
  }).finally(() => agent.destroy());
}

async function selfTest() {
  if (parseTrace('test=1\nip=203.0.113.17\n', {}).Ipv4 !== '203.0.113.17') throw new Error('Trace parse failed');
  for (const body of ['ip=::1\n', 'ip=203.0.113.17\nip=203.0.113.18\n', 'other=1\n']) {
    try { parseTrace(body, {}); } catch { continue; }
    throw new Error('Invalid trace accepted');
  }
  let connections = 0;
  let request = '';
  const server = net.createServer((socket) => {
    connections++;
    socket.setEncoding('ascii');
    socket.on('data', (part) => {
      request += part;
      if (request.endsWith('\r\n\r\n')) socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    let rejected = false;
    try { await openTunnel(server.address().port, cloudflare, 'dGVzdDp0ZXN0'); } catch { rejected = true; }
    if (!rejected || connections !== 1 || !request.startsWith('CONNECT 1.1.1.1:443 HTTP/1.1\r\n')) {
      throw new Error('The rejected tunnel did not stop the query');
    }
  } finally {
    server.close();
  }
  console.log('PASS IPv4 parsing and single loopback tunnel rejection');
}

async function observeProvider(input, provider, endsAt, ca) {
  let stage = 'CONNECT';
  let proxy;
  let connection;
  let issued = false;
  let sourcePort = null;
  let connectedUtc = null;
  const timeout = new AbortController();
  const deadline = setTimeout(() => {
    timeout.abort();
    connection?.destroy(new Error('ProbeDeadline'));
  }, Math.max(1, endsAt - performance.now()));
  try {
    proxy = await openTunnel(input.port, provider, input.authorization, timeout.signal, (port, utc) => {
      sourcePort = port;
      connectedUtc = utc;
    });
    stage = 'TLS';
    connection = tls.connect({
      socket: proxy,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ALPNProtocols: ['http/1.1'],
      ca,
      servername: net.isIP(provider.host) ? undefined : provider.host,
      checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(provider.host, certificate)
    });
    await once(connection, 'secureConnect');
    stage = 'Trace';
    issued = true;
    const includeCountry = input.includeCountry === true;
    const sample = await readAddress(connection, provider, timeout.signal, includeCountry);
    if (performance.now() >= endsAt) throw new Error('ProbeDeadline');
    if (includeCountry && provider === ipify) sample.CountryCode = null;
    return { Ok: true, Provider: provider.id, Stage: stage, QueryIssued: issued, SourcePort: sourcePort, ConnectedUtc: connectedUtc, ...sample };
  } catch (error) {
    const outcome = stage === 'TLS' && !timeout.signal.aborted && error.code === 'ECONNRESET' ?
      'PeerClosedBeforeTls' : 'Recheck';
    return { Ok: false, Provider: provider.id, Stage: stage, QueryIssued: issued, SourcePort: sourcePort,
      ConnectedUtc: connectedUtc, Outcome: outcome, Error: timeout.signal.aborted ? 'ProbeDeadline' : error.code || error.message };
  } finally {
    clearTimeout(deadline);
    connection?.destroy();
    proxy?.destroy();
  }
}

export async function observeExit(input, { ca, protectedListener = true } = {}) {
  const deadlineMs = input?.deadlineMs ?? maxDeadlineMs;
  const authenticated = typeof input?.authorization === 'string' && /^[A-Za-z0-9+/]{16,160}={0,2}$/.test(input.authorization);
  if (!Number.isInteger(input?.port) || input.port <= 1023 || input.port >= 49152 ||
      (!authenticated && !(protectedListener && input.authorization === undefined)) ||
      (input.backupExitLookup !== undefined && typeof input.backupExitLookup !== 'boolean') ||
      (input.includeCountry !== undefined && typeof input.includeCountry !== 'boolean') ||
      !Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > maxDeadlineMs) {
    return { Ok: false, Stage: 'Input', QueryIssued: false, Outcome: 'Recheck', Error: 'InvalidRelay' };
  }

  const started = performance.now();
  const deadline = started + deadlineMs;
  // Leave the pinned relay enough time to finish its five-second first-hop dial budget.
  const primaryMs = input.backupExitLookup ? Math.min(deadlineMs, Math.max(5500, deadlineMs - 5500)) : deadlineMs;
  const primary = await observeProvider(input, cloudflare, started + primaryMs, ca);
  // Accept the first valid IPv4, including a mismatch for the controller to act on.
  // A pre-TLS reset may be corroborated by the pinned relay and must be surfaced intact.
  const useBackup = !primary.Ok && (primary.Stage === 'Trace' ||
    (primary.Stage === 'TLS' && primary.Error === 'ProbeDeadline'));
  if (input.backupExitLookup === true && useBackup && deadline - performance.now() >= 1) {
    return observeProvider(input, ipify, deadline, ca);
  }
  return primary;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--self-test') {
    await selfTest();
  } else {
    let result;
    try {
      const input = JSON.parse(readFileSync(0, 'utf8').replace(/^\uFEFF/, ''));
      result = await observeExit(input, { protectedListener: process.argv[2] === '--protected-listener' });
    } catch {
      result = { Ok: false, Stage: 'Input', QueryIssued: false, Outcome: 'Recheck', Error: 'InvalidRelay' };
    }
    console.log(JSON.stringify(result));
    if (!result.Ok) process.exitCode = 1;
  }
}
