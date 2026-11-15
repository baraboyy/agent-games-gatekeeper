/*
 * Agent Games — Proof Gatekeeper SHARED CORE (transport-agnostic).
 *
 * This module holds ALL request-handling logic for the gatekeeper agent:
 * raw-body HMAC-SHA256 verification, signed responses, the preflight reply
 * { ok: true, protocolVersion: "v1" }, and the deterministic decision logic
 * for the 7 documented trap varieties (see ../PROTOCOL.md).
 *
 * It is used unchanged by both runtimes:
 *   - Node:  ../agent.js  (require('./deploy/core.cjs')) — node:http bootstrap
 *            with an fs-backed persistent store.
 *   - Deno:  ./main.js    (import core from "./core.cjs") — Deno.serve
 *            bootstrap with an in-memory store (Deno Deploy isolates and
 *            filesystems are ephemeral; see DEPLOY.md).
 *
 * The code is CommonJS and only uses node:crypto / node:buffer, which Deno
 * (including Deno Deploy) supports natively in .cjs files — so the exact
 * same synchronous HMAC code path runs in both runtimes.
 *
 * State is injected as a `store`:
 *   { seenProofTx: Set<string>, responses: Map<string, object>, save(): void }
 * `save()` is called after every decision, exactly where the original
 * agent.js called saveState(); the Node bootstrap's save() persists to disk,
 * the Deno bootstrap's save() is a no-op over in-memory state.
 *
 * Secrets come from the caller: createCore({ secret, store }).
 * NOTE: the docs do not specify the signature header encoding; this core
 * uses lowercase hex HMAC-SHA256 (see ../PROTOCOL.md §1, UNSPECIFIED).
 */
'use strict';

const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');

function createCore({ secret, store }) {
  if (!secret) throw new Error('createCore: a non-empty secret is required');
  if (!store || !(store.seenProofTx instanceof Set) || !(store.responses instanceof Map) || typeof store.save !== 'function') {
    throw new Error('createCore: store must be { seenProofTx: Set, responses: Map, save(): void }');
  }

  // ---------- HMAC helpers ----------
  function sign(rawBody) {
    return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  }
  function signatureValid(rawBody, headerValue) {
    if (typeof headerValue !== 'string' || headerValue.length === 0) return false;
    const expected = Buffer.from(sign(rawBody), 'utf8');
    const given = Buffer.from(headerValue.trim(), 'utf8');
    return expected.length === given.length && crypto.timingSafeEqual(expected, given);
  }

  // ---------- Groth16 proof step (PLACEHOLDER) ----------
  /*
   * TODO(real-proof): generate the agent's own Groth16 proof of the decision
   * with snarkjs using ../circuits/gatekeeper.wasm +
   * ../circuits/gatekeeper_final.zkey, and — if required — submit it via
   * Kurier (POST https://api.kurier.xyz/api/v1/submit-proof/$KURIER_API_KEY,
   * vk = gatekeeper vk_hash
   * 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
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
    if (typeof task.task_id === 'string' && store.responses.has(task.task_id)) {
      return store.responses.get(task.task_id);
    }

    let decision;
    try {
      const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : '';
      if (proofTx && store.seenProofTx.has(proofTx)) {
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
    if (typeof input.proof_tx === 'string' && input.proof_tx) store.seenProofTx.add(input.proof_tx);

    // Attach the agent's own proof on provable tasks (all but PROOF_REUSED).
    if (decision.reason_code !== 'PROOF_REUSED') {
      const p = await generateDecisionProof(task, decision);
      if (p) { decision.proof = p.proof; decision.public_signals = p.publicSignals; }
    }

    if (typeof task.task_id === 'string') store.responses.set(task.task_id, decision);
    store.save();
    return decision;
  }

  // ---------- Transport-agnostic request handling ----------
  // respond(): serialize + sign a JSON response object.
  function respond(status, obj) {
    const raw = Buffer.from(JSON.stringify(obj), 'utf8');
    return { status, raw, signature: sign(raw) };
  }

  // handleRequest(rawBody, signatureHeader) -> { status, raw, signature }
  // Mirrors the original agent.js POST flow exactly: verify HMAC over the RAW
  // body BEFORE parsing, dispatch on msg.type, fail closed on internal error.
  async function handleRequest(rawBody, signatureHeader) {
    const raw = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
    if (!signatureValid(raw, signatureHeader)) {
      return respond(401, { error: 'bad_signature' });
    }
    let msg;
    try { msg = JSON.parse(raw.toString('utf8')); } catch {
      return respond(400, { error: 'bad_json' });
    }
    try {
      if (msg && msg.type === 'agent-games.preflight.v1') {
        return respond(200, { ok: true, protocolVersion: 'v1' });
      } else if (msg && msg.type === 'agent-games.proof-gatekeeper.v1') {
        return respond(200, await decide(msg));
      } else {
        return respond(400, { error: 'unknown_type' });
      }
    } catch {
      // Fail closed on any internal error during a task.
      if (msg && msg.type === 'agent-games.proof-gatekeeper.v1') {
        return respond(200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR', proof_tx: msg.input && msg.input.proof_tx || null });
      } else {
        return respond(500, { error: 'internal' });
      }
    }
  }

  return { sign, signatureValid, decide, respond, handleRequest };
}

module.exports = { createCore };
