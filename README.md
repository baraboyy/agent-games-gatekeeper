# Agent Games — Proof Gatekeeper agent (scaffold)

- `PROTOCOL.md` — faithful protocol extraction from agentgames.zkverify.io (/build, /guide, /rules, /events/proof-gatekeeper, /api/circuit-info), with UNSPECIFIED items marked.
- `agent.js` — zero-dependency Node HTTP service: HMAC-SHA256 verify (raw body, before parsing), signed responses, preflight `{ ok: true, protocolVersion: "v1" }`, deterministic decision logic for all 7 documented trap varieties, task_id idempotency, persisted seen-proof set. Groth16 proof generation is a placeholder (`generateDecisionProof`) — see PROTOCOL.md §5 for the blockers.
- `selftest.js` — `node selftest.js` simulates signed platform requests and verifies signed responses.
- `circuits/` — gatekeeper.wasm + gatekeeper_final.zkey downloaded from the site (sha256 in PROTOCOL.md §6).
- `tools/cloudflared` — tunnel binary for the public-HTTPS endpoint (availability verified only; nothing exposed yet).

Run locally:

```
AGENT_GAMES_HMAC_SECRET=<any-test-value> node agent.js   # listens on :8080/agent
node selftest.js
```

Not live: no dashboard registration, no real HMAC secret, no proof generation/submission yet. See PROTOCOL.md §8 and the final report for what's still needed.
