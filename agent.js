#!/usr/bin/env node
/*
 * Agent Games — Proof Gatekeeper agent (Node bootstrap).
 *
 * All request-handling logic (raw-body HMAC-SHA256 verify, signed responses,
 * preflight, gatekeeper decision logic) lives in the shared core,
 * deploy/core.cjs, which is also used by the Deno Deploy entrypoint
 * (deploy/main.js). This file is only the node:http plumbing plus the
 * fs-backed persistent store (seen proof_tx set + task_id idempotency
 * cache), in the same on-disk format as before the refactor.
 *
 * Protocol: see PROTOCOL.md. Secrets come from the environment only:
 * AGENT_GAMES_HMAC_SECRET.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { createCore } = require('./deploy/core.cjs');

const PORT = Number(process.env.PORT || 8080);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DATA_DIR = process.env.AGENT_DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

if (!SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set (see .env.example). Refusing to start.');
  process.exit(1);
}

// ---------- Persistent store (fs-backed; same format as the original) ----------
function loadStore() {
  let seenProofTx = new Set();
  let responses = new Map();
  try {
    const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    seenProofTx = new Set(s.seenProofTx || []);
    responses = new Map(Object.entries(s.responses || {}));
  } catch {
    // No (readable) state file: start fresh.
  }
  const store = {
    seenProofTx,
    responses,
    save() {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = STATE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({
        seenProofTx: [...store.seenProofTx],
        responses: Object.fromEntries(store.responses),
      }));
      fs.renameSync(tmp, STATE_FILE);
    },
  };
  return store;
}

const core = createCore({ secret: SECRET, store: loadStore() });

// ---------- HTTP plumbing ----------
function sendResult(res, { status, raw, signature }) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': signature,
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
    sendResult(res, core.respond(404, { error: 'not_found' }));
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    sendResult(res, await core.handleRequest(Buffer.concat(chunks), req.headers['x-agent-games-signature']));
  });
});

server.listen(PORT, () => {
  console.log(`agent-games gatekeeper scaffold listening on :${PORT}${AGENT_PATH}`);
});
