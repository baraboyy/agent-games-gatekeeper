/*
 * Agent Games — Proof Gatekeeper agent (Deno Deploy entrypoint).
 *
 * Runs the SAME shared core as the Node bootstrap (../agent.js):
 * core.cjs holds all request-handling logic (raw-body HMAC-SHA256 verify,
 * signed responses, preflight { ok: true, protocolVersion: "v1" },
 * gatekeeper decision logic). This file is only the Deno.serve bootstrap.
 *
 * Deno Deploy settings (see DEPLOY.md):
 *   - Entrypoint: deploy/main.js
 *   - Env var:    AGENT_GAMES_HMAC_SECRET = the platform secret from the
 *                 dashboard's Rotate Secret (a placeholder fails preflight).
 *   - Public URL: https://<project>.deno.dev/agent
 *
 * Differences from the Node runtime, by necessity:
 *   - State store is IN-MEMORY. Deno Deploy isolates are ephemeral and the
 *     filesystem does not persist, so the seen-proof_tx set and the task_id
 *     idempotency cache live only as long as the isolate. Decision logic is
 *     identical; only persistence across restarts is best-effort. (Deno KV
 *     is the upgrade path if cross-isolate persistence is ever required.)
 *   - HMAC uses node:crypto via Deno's Node compatibility (core.cjs is a
 *     CommonJS module; Deno imports it with module.exports as the default
 *     export). No logic change was needed.
 */

import coreModule from "./core.cjs";

const { createCore } = coreModule;

const SECRET = Deno.env.get("AGENT_GAMES_HMAC_SECRET") ?? "";
if (!SECRET) {
  // Fail closed, mirroring the Node bootstrap: never serve without a secret.
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  throw new Error("AGENT_GAMES_HMAC_SECRET is not set");
}
const AGENT_PATH = Deno.env.get("AGENT_PATH") ?? "/agent";

const store = {
  seenProofTx: new Set(),
  responses: new Map(),
  save() {
    // In-memory only on Deno Deploy — nothing to persist to.
  },
};

const core = createCore({ secret: SECRET, store });

function toResponse({ status, raw, signature }) {
  return new Response(raw, {
    status,
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": signature,
    },
  });
}

const portEnv = Deno.env.get("PORT");
const serveOptions = portEnv ? { port: Number(portEnv) } : {};

Deno.serve(serveOptions, async (req) => {
  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/healthz") {
    // Unsigned liveness probe for hosting only; the platform uses AGENT_PATH.
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  if (req.method !== "POST" || url.pathname !== AGENT_PATH) {
    return toResponse(core.respond(404, { error: "not_found" }));
  }
  const raw = new Uint8Array(await req.arrayBuffer());
  const result = await core.handleRequest(
    raw,
    req.headers.get("x-agent-games-signature"),
  );
  return toResponse(result);
});
