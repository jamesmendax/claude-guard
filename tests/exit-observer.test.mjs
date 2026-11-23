import assert from 'node:assert/strict';
import { randomInt } from 'node:crypto';
import { test } from 'node:test';
import { observeExit } from './cloudflare-exit-probe.mjs';
import { observeFixture, startExitFixture } from './exit-observer-fixture.mjs';

const expectedIpv4 = '203.0.113.17';
const otherIpv4 = '203.0.113.18';

async function withRelay(cloudflare, ipify, check) {
  let fixture;
  for (let tries = 0; tries < 10; tries++) {
    try {
      fixture = await startExitFixture(randomInt(20000, 48000), () => ({ cloudflare, ipify, expectedIpv4, otherIpv4 }));
      break;
    } catch (error) {
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  assert.ok(fixture, 'a loopback port is available');
  try {
    await check(fixture);
  } finally {
    await fixture.stop();
  }
}

test('Primary success and authoritative mismatch each skip ipify', async () => {
  for (const [mode, address] of [['match', expectedIpv4], ['mismatch', otherIpv4]]) {
    await withRelay(mode, 'match', async ({ port, requests }) => {
      const result = await observeFixture({ port, backupExitLookup: true });
      assert.equal(result.Ok, true);
      assert.equal(result.Provider, 'CloudflareTrace');
      assert.equal(result.Ipv4, address);
      assert.deepEqual(requests, ['CloudflareTrace']);
    });
  }
});

test('Absent and false backup settings preserve Cloudflare-only behavior', async () => {
  await withRelay('invalid', 'match', async ({ port, requests }) => {
    for (const settings of [{}, { backupExitLookup: false }]) {
      const result = await observeFixture({ port, ...settings });
      assert.equal(result.Ok, false);
      assert.equal(result.Provider, 'CloudflareTrace');
    }
    assert.deepEqual(requests, ['CloudflareTrace', 'CloudflareTrace']);
  });
});

test('After a provider outage the approved backup reports its own exact IPv4', async () => {
  for (const [mode, address] of [['match', expectedIpv4], ['mismatch', otherIpv4]]) {
    await withRelay('reject', mode, async ({ port, requests }) => {
      const result = await observeFixture({ port, backupExitLookup: true });
      assert.equal(result.Ok, true);
      assert.equal(result.Provider, 'Ipify');
      assert.equal(result.Ipv4, address);
      assert.deepEqual(requests, ['CloudflareTrace', 'Ipify']);
    });
  }
});

test('After a primary HTTP timeout the backup uses the remaining round budget', async () => {
  await withRelay('timeout', 'match', async ({ port, requests }) => {
    const result = await observeFixture({ port, backupExitLookup: true, deadlineMs: 6500 });
    assert.equal(result.Ok, true);
    assert.equal(result.Provider, 'Ipify');
    assert.equal(result.Ipv4, expectedIpv4);
    assert.deepEqual(requests, ['CloudflareTrace', 'Ipify']);
  });
});

test('Two unavailable providers share one hard deadline and produce no usable IPv4', async () => {
  await withRelay('reject', 'timeout', async ({ port, requests }) => {
    const started = performance.now();
    const result = await observeFixture({ port, backupExitLookup: true, deadlineMs: 650 });
    assert.equal(result.Ok, false);
    assert.equal(result.Provider, 'Ipify');
    assert.equal(result.Error, 'ProbeDeadline');
    assert.equal(result.Ipv4, undefined);
    assert.ok(performance.now() - started < 1200, 'the backup received only the remaining time');
    assert.deepEqual(requests, ['CloudflareTrace', 'Ipify']);
  });
});

test('A pre-TLS peer reset is retained to verify first-hop loss, without backup', async () => {
  await withRelay('reset', 'match', async ({ port, requests }) => {
    const result = await observeFixture({ port, backupExitLookup: true });
    assert.equal(result.Ok, false);
    assert.equal(result.Provider, 'CloudflareTrace');
    assert.equal(result.Outcome, 'PeerClosedBeforeTls');
    assert.equal(result.QueryIssued, false);
    assert.deepEqual(requests, ['CloudflareTrace']);
  });
});

test('Normal invocation rejects the fixture-only CA and caller-supplied CA input', async () => {
  await withRelay('match', 'match', async ({ port, requests }) => {
    const result = await observeExit({ port, backupExitLookup: true, ca: 'untrusted caller input' });
    assert.equal(result.Ok, false);
    assert.equal(result.Stage, 'TLS');
    assert.equal(result.QueryIssued, false);
    assert.deepEqual(requests, ['CloudflareTrace']);
  });
});
