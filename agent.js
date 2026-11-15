#!/usr/bin/env node
/*
 * Agent Games — Proof Gatekeeper agent (SCAFFOLD).
 *
 * Implements the protocol documented in PROTOCOL.md (extracted from
 * https://agentgames.zkverify.io/build, /guide, /rules, /events/proof-gatekeeper):
 *   - POST <AGENT_PATH> (default /agent), HMAC-SHA256 over the RAW body,
 *     verified BEFORE JSON parsing; every response signed the same way.
 *   - Preflight:  type "agent-games.preflight.v1"  -> { ok: true, protocolVersion: "v1" }
 *   - Tasks:      type "agent-games.proof-gatekeeper.v1" -> { decision, reason_code, proof_tx, ... }
 *   - Deterministic decision logic for the 7 documented trap varieties.
 *   - Groth16 proof generation is a PLACEHOLDER (see generateDecisionProof):
 *     the docs do not specify the gatekeeper circuit's input layout, and no
 *     Kurier API key / funded Volta account exists yet.
 *
 * Secrets come from the environment only: AGENT_GAMES_HMAC_SECRET.
 * NOTE: the docs do not specify the signature header encoding; this scaffold
 * uses lowercase hex HMAC-SHA256 (see PROTOCOL.md §1, UNSPECIFIED).
 */
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8080);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DATA_DIR = process.env.AGENT_DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

if (!SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set (see .env.example). Refusing to start.');
  process.exit(1);
}

// ---------- HMAC helpers ----------
function sign(rawBody) {
  return crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');
}
function signatureValid(rawBody, headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return false;
  const expected = Buffer.from(sign(rawBody), 'utf8');
  const given = Buffer.from(headerValue.trim(), 'utf8');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

// ---------- Persistent state: seen proof_tx set + task_id idempotency cache ----------
function loadState() {
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    return { seenProofTx: new Set(s.seenProofTx || []), responses: new Map(Object.entries(s.responses || {})) };
  } catch {
    return { seenProofTx: new Set(), responses: new Map() };
  }
}
const state = loadState();
function saveState() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({
    seenProofTx: [...state.seenProofTx],
    responses: Object.fromEntries(state.responses),
  }));
  fs.renameSync(tmp, STATE_FILE);
}

// ---------- Groth16 proof step (PLACEHOLDER) ----------
/*
 * TODO(real-proof): generate the agent's own Groth16 proof of the decision
 * with snarkjs using circuits/gatekeeper.wasm + circuits/gatekeeper_final.zkey,
 * and — if required — submit it via Kurier (POST
 * https://api.kurier.xyz/api/v1/submit-proof/$KURIER_API_KEY, vk = gatekeeper
 * vk_hash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
 * and wait for Finalized.
 *
 * BLOCKED ON: (1) the circuit's witness-input / public-signal layout, which
 * the public docs do NOT specify (PROTOCOL.md §5); (2) a KURIER_API_KEY or a
 * funded Volta account for the submission path.
 *
 * Until then this returns null and the response omits proof/public_signals
 * (documented cost on a provable task: -2 — accepted for the scaffold only).
 * PROOF_REUSED responses never carry a proof (docs: those tasks "have no
 * proof to submit").
 */
async function generateDecisionProof(/* task, decision */) {
  return null; // { proof, publicSignals }
}

// ---------- Decision logic (deterministic, fail closed) ----------
// Check order is ours (docs give no precedence — PROTOCOL.md §4). Replay is
// checked first so a reused proof is always caught; then the documented
// Security-checklist field checks; anything malformed fails closed as REJECT.
async function decide(task) {
  const input = (task && typeof task === 'object') ? task.input : undefined;
  const base = { proof_tx: input && typeof input.proof_tx === 'string' ? input.proof_tx : null };

  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: 'MALFORMED_TASK', ...base };
  }

  // Idempotency: platform retries reuse the same task_id -> same response.
  if (typeof task.task_id === 'string' && state.responses.has(task.task_id)) {
    return state.responses.get(task.task_id);
  }

  let decision;
  try {
    const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : '';
    if (proofTx && state.seenProofTx.has(proofTx)) {
      decision = { decision: 'REJECT', reason_code: 'PROOF_REUSED', ...base };
    } else if (String(input.proof_vk) !== String(input.registered_vk)) {
      decision = { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', ...base };
    } else if (BigInt(input.public_balance) < BigInt(input.minimum)) {
      decision = { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', ...base };
    } else if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) {
      decision = { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', ...base };
    } else if (BigInt(input.amount) > BigInt(input.max_transfer)) {
      decision = { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', ...base };
    } else if (BigInt(input.current_block) > BigInt(input.expiry_block)) {
      // Boundary (">" vs ">=") is UNSPECIFIED in the docs; "expiry has passed" read as current > expiry.
      decision = { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', ...base };
    } else {
      decision = { decision: 'APPROVE', reason_code: 'VALID_CONDITION', ...base };
    }
  } catch {
    // Any unparseable field (bad BigInt, missing value, ...) fails closed.
    decision = { decision: 'REJECT', reason_code: 'MALFORMED_TASK', ...base };
  }

  // Record the proof reference as seen (docs: a reference "already accepted in
  // a previous task" must be rejected on re-submission).
  if (typeof input.proof_tx === 'string' && input.proof_tx) state.seenProofTx.add(input.proof_tx);

  // Attach the agent's own proof on provable tasks (all but PROOF_REUSED).
  if (decision.reason_code !== 'PROOF_REUSED') {
    const p = await generateDecisionProof(task, decision);
    if (p) { decision.proof = p.proof; decision.public_signals = p.publicSignals; }
  }

  if (typeof task.task_id === 'string') state.responses.set(task.task_id, decision);
  saveState();
  return decision;
}

// ---------- HTTP plumbing ----------
function sendSigned(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': sign(raw),
  });
  res.end(raw);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    // Unsigned liveness probe for hosting only; the platform uses AGENT_PATH.
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== 'POST' || req.url !== AGENT_PATH) {
    sendSigned(res, 404, { error: 'not_found' });
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    // Verify HMAC over the RAW body BEFORE parsing (docs requirement).
    if (!signatureValid(raw, req.headers['x-agent-games-signature'])) {
      sendSigned(res, 401, { error: 'bad_signature' });
      return;
    }
    let msg;
    try { msg = JSON.parse(raw.toString('utf8')); } catch {
      sendSigned(res, 400, { error: 'bad_json' });
      return;
    }
    try {
      if (msg && msg.type === 'agent-games.preflight.v1') {
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      } else if (msg && msg.type === 'agent-games.proof-gatekeeper.v1') {
        sendSigned(res, 200, await decide(msg));
      } else {
        sendSigned(res, 400, { error: 'unknown_type' });
      }
    } catch {
      // Fail closed on any internal error during a task.
      if (msg && msg.type === 'agent-games.proof-gatekeeper.v1') {
        sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR', proof_tx: msg.input && msg.input.proof_tx || null });
      } else {
        sendSigned(res, 500, { error: 'internal' });
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`agent-games gatekeeper scaffold listening on :${PORT}${AGENT_PATH}`);
});
