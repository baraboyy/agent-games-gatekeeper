#!/usr/bin/env node
/*
 * Local self-test for the Proof Gatekeeper scaffold.
 * Starts agent.js on a scratch port with a throwaway HMAC secret and a temp
 * data dir, then simulates signed platform requests and verifies the signed
 * responses: preflight, one valid task, every documented trap, proof reuse,
 * task_id idempotency, and bad-signature rejection.
 */
'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 18099;
const SECRET = 'selftest-secret-not-a-real-one';
const URL = `http://127.0.0.1:${PORT}/agent`;

const sign = (raw) => crypto.createHmac('sha256', SECRET).update(raw).digest('hex');

async function post(obj, { badSig = false } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const res = await fetch(URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(raw),
    },
    body: raw,
  });
  const text = await res.text();
  const sigOk = res.headers.get('x-agent-games-signature') === sign(Buffer.from(text, 'utf8'));
  return { status: res.status, body: JSON.parse(text), sigOk };
}

let failures = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
  if (!cond) failures++;
}

const baseInput = {
  registered_vk: '0xREGVK',
  proof_vk: '0xREGVK',
  minimum: '1000',
  public_balance: '1460',
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: '0xDe429f01',
  condition_recipient: '0xDe429f01',
  amount: '500',
  max_transfer: '1000',
  proof_tx: '0xTX1',
};
const task = (task_id, overrides = {}) => ({
  type: 'agent-games.proof-gatekeeper.v1',
  task_id,
  mode: 'competition',
  issued_at: '2026-11-15T10:00:00Z',
  deadline_at: '2026-11-15T10:01:00Z',
  input: { ...baseInput, ...overrides },
});

(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-selftest-'));
  const child = spawn(process.execPath, [path.join(__dirname, 'agent.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, AGENT_DATA_DIR: dataDir },
    stdio: 'pipe',
  });
  try {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('server start timeout')), 5000);
      child.stdout.on('data', (d) => { if (String(d).includes('listening')) { clearTimeout(to); resolve(); } });
      child.on('exit', (c) => reject(new Error('server exited early: ' + c)));
    });

    // Preflight
    let r = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: '2026-11-15T10:00:00Z', nonce: 'abc123' });
    check('preflight -> { ok: true, protocolVersion: "v1" }', r.status === 200 && r.body.ok === true && r.body.protocolVersion === 'v1');
    check('preflight response signature valid', r.sigOk);

    // Valid task -> APPROVE / VALID_CONDITION
    r = await post(task('gk_t1'));
    check('valid task -> APPROVE/VALID_CONDITION', r.body.decision === 'APPROVE' && r.body.reason_code === 'VALID_CONDITION', JSON.stringify(r.body));
    check('task response signature valid', r.sigOk);
    check('response echoes proof_tx', r.body.proof_tx === '0xTX1');

    // Traps (each with a fresh proof_tx so reuse doesn't mask the trap)
    r = await post(task('gk_t2', { proof_tx: '0xTX2', proof_vk: '0xOTHER' }));
    check('VK substitution -> REJECT/VK_SUBSTITUTION', r.body.decision === 'REJECT' && r.body.reason_code === 'VK_SUBSTITUTION');
    r = await post(task('gk_t3', { proof_tx: '0xTX3', public_balance: '900' }));
    check('threshold -> REJECT/THRESHOLD_MISMATCH', r.body.reason_code === 'THRESHOLD_MISMATCH');
    r = await post(task('gk_t4', { proof_tx: '0xTX4', recipient: '0xSomeoneElse' }));
    check('recipient -> REJECT/RECIPIENT_MISMATCH', r.body.reason_code === 'RECIPIENT_MISMATCH');
    r = await post(task('gk_t5', { proof_tx: '0xTX5', amount: '1001' }));
    check('amount -> REJECT/AMOUNT_OVERFLOW', r.body.reason_code === 'AMOUNT_OVERFLOW');
    r = await post(task('gk_t6', { proof_tx: '0xTX6', current_block: 8430001 }));
    check('expired -> REJECT/EXPIRED_CONDITION', r.body.reason_code === 'EXPIRED_CONDITION');

    // Proof reuse: 0xTX1 was consumed by gk_t1; a NEW task_id reusing it must be rejected.
    r = await post(task('gk_t7', { proof_tx: '0xTX1' }));
    check('reused proof_tx -> REJECT/PROOF_REUSED', r.body.decision === 'REJECT' && r.body.reason_code === 'PROOF_REUSED');

    // Idempotency: same task_id retried returns the cached response, not PROOF_REUSED.
    r = await post(task('gk_t1'));
    check('same task_id retry -> cached APPROVE', r.body.decision === 'APPROVE' && r.body.reason_code === 'VALID_CONDITION');

    // Bad signature -> 401
    r = await post(task('gk_t8', { proof_tx: '0xTX8' }), { badSig: true });
    check('bad signature -> 401', r.status === 401);

    console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
})().catch((e) => { console.error('SELFTEST ERROR:', e.message); process.exit(1); });
