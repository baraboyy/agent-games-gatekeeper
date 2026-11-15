# Deno Deploy — gatekeeper agent deployment notes

Free tier, no sleep, public HTTPS on port 443 — satisfies the platform's
endpoint rules (../PROTOCOL.md §1). The Deno runtime runs the **same shared
core** as the Node bootstrap; nothing about the protocol logic differs.

## Files

| file | role |
|---|---|
| `deploy/main.js` | **Entrypoint** for Deno Deploy (Deno.serve bootstrap) |
| `deploy/core.cjs` | Shared core: HMAC-SHA256 verify/sign, preflight, decision logic. Imported by `main.js` (ESM default import of the CJS module) and by `../agent.js` (Node `require`). |
| `../agent.js` | Node bootstrap (unchanged behavior; now a thin wrapper over `core.cjs`) |

HMAC choice: `node:crypto` (`createHmac` + `timingSafeEqual`) inside
`core.cjs`. Deno — including Deno Deploy — supports `node:crypto` in
CommonJS modules natively, so the identical synchronous code path runs in
both runtimes. No WebCrypto rewrite was needed.

## Deno Deploy project settings

- **Source:** GitHub repo `baraboyy/agent-games-gatekeeper`, production
  branch = the repo's default branch (`main`).
- **Entrypoint:** `deploy/main.js`
- **Build step / framework preset:** none (raw Deno project; no build
  command, no root-directory change).
- **Environment variables** (set for Production, and Preview if used):
  - `AGENT_GAMES_HMAC_SECRET` = **the platform secret** from the Agent
    Games dashboard → agent settings → **Rotate Secret**. It is shown
    exactly once; a placeholder or mismatched secret fails preflight with
    a signature error (PROTOCOL.md §1). After rotating the secret on the
    Agent Games side, update this variable and redeploy.
  - `AGENT_PATH` — optional; defaults to `/agent`. Leave unset.
  - `PORT` — do **not** set; Deno Deploy manages it.
- **Expected public URL form:** `https://<project>.deno.dev`
  (Deno may append a suffix if the project name is taken globally — read
  the exact production domain off the project page after the first deploy.)
- **Handler URL to register on the Agent Games dashboard** (full path —
  the platform posts to the URL exactly as registered):
  `https://<project>.deno.dev/agent`

## Runtime differences vs Node (accepted, documented)

- **State is in-memory only.** `main.js` gives the core a store backed by
  a `Set`/`Map` with a no-op `save()`: Deno Deploy isolates are ephemeral
  and the filesystem does not persist, so the seen-`proof_tx` set and the
  `task_id` idempotency cache survive only within a warm isolate. The
  decision logic itself is byte-identical. (Upgrade path if ever needed:
  Deno KV.)
- Everything else — raw-body HMAC verification before parsing, signed
  responses, preflight body, trap reason codes, fail-closed behavior — is
  the shared core, unchanged.

## Local verification (2026-11-15, this workspace)

- Deno installed locally from GitHub releases: **deno 2.9.8**
  (x86_64-unknown-linux-gnu).
- Node regression gate: `node selftest.js` = **13/13 PASS before and
  after** the core extraction — Node behavior is unchanged.
- Deno run: `deno run --allow-env --allow-net deploy/main.js` with the
  test secret from `../agent.env`, on port 18098; signed-request check
  against `http://127.0.0.1:18098/agent` = **8/8 PASS**:
  - preflight → `200 {"ok":true,"protocolVersion":"v1"}`, response
    signature valid;
  - VALID_CONDITION task → `APPROVE / VALID_CONDITION`, signature valid,
    `proof_tx` echoed;
  - VK-substitution task → `REJECT / VK_SUBSTITUTION`, signature valid;
  - bad signature → `401`.
- Known scaffold limits are unchanged by this port: Groth16 proof
  generation is still a placeholder (−2 on provable tasks, PROTOCOL.md
  §5), and the signature header encoding assumption is still lowercase
  hex (PROTOCOL.md §1, UNSPECIFIED — to be confirmed by the first real
  preflight).

## Browser deployment steps (dash.deno.com) — for the operator

1. Go to **https://dash.deno.com** and **sign in with GitHub** (the
   `baraboyy` account that owns the repo).
2. **New Project** → choose the GitHub deployment option → if prompted,
   install/authorize the **Deno Deploy GitHub app** and grant it access
   to the repository **`baraboyy/agent-games-gatekeeper`**.
3. Select that repository and its default branch (`main`) as the
   production branch.
4. When asked for the entrypoint, pick **`deploy/main.js`**. No build
   step / no framework preset.
5. In the project's **Settings → Environment Variables**, add
   `AGENT_GAMES_HMAC_SECRET` with the value from the Agent Games
   dashboard's **Rotate Secret** (do this before expecting preflight to
   pass; the value can be set before or right after the first deploy,
   followed by a redeploy).
6. Deploy. Open the production URL and note the exact domain
   (`https://<project>.deno.dev`).
7. Register **`https://<project>.deno.dev/agent`** (with the `/agent`
   path) as the agent endpoint on the Agent Games dashboard, then run
   the platform's preflight from the dashboard.
