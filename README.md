# helpscout-webhook-shim

A tiny signing proxy that lets **Help Scout** webhooks reach **Hermes**.

## Why this exists

The two halves don't line up natively:

| | Algorithm | Encoding | Header |
|---|---|---|---|
| Help Scout signs | HMAC-SHA1 | base64 | `X-HelpScout-Signature` |
| Hermes verifies (generic) | HMAC-SHA256 | hex | `X-Webhook-Signature` |

Hermes's webhook adapter is SHA256-only (GitHub/GitLab/generic) with no
SHA1 or custom-header option, so Help Scout **cannot POST to Hermes directly** —
the signature will never validate. This shim is the translator:

```
Help Scout ──HTTPS──▶ HTTPS ingress ──▶ shim :9100 ──▶ Hermes webhook :8644
  SHA1 / base64        (tunnel / proxy)   verify SHA1,     generic SHA256 / hex
  X-HelpScout-Sig                         re-sign SHA256
```

It verifies Help Scout's signature over the **raw** body (real authentication —
Help Scout is unattended and can't do interactive auth), then re-signs the exact
same bytes as SHA256 and forwards to Hermes.

## Files

| File | Purpose |
|---|---|
| `relay.py` | The shim (Flask + waitress). |
| `Dockerfile` / `docker-compose.yml` | Container, host networking, binds to `127.0.0.1`. |
| `.env.example` | Secret template — copy to `.env` on the box. |
| `docs/hermes-config.yaml` | Route to merge into `~/.hermes/config.yaml`. |
| `smoke-test.sh` | Signs a fake event and POSTs it to the shim. |

## Deploy (on the Hermes box)

### 1. Secrets

```bash
cp .env.example .env
sed -i "s|^HS_WEBHOOK_SECRET=.*|HS_WEBHOOK_SECRET=$(openssl rand -hex 20)|" .env
sed -i "s|^WEBHOOK_SECRET=.*|WEBHOOK_SECRET=$(openssl rand -hex 32)|" .env
chmod 600 .env
```

- `HS_WEBHOOK_SECRET` (≤40 chars — hex-20 is exactly 40) → paste into Help Scout later.
- `WEBHOOK_SECRET` → Hermes's global webhook secret; the shim re-signs with it.

### 2. Point Hermes at the same secret + add the route

```bash
grep -q '^WEBHOOK_SECRET=' ~/.hermes/.env || \
  echo "WEBHOOK_SECRET=$(grep '^WEBHOOK_SECRET=' .env | cut -d= -f2)" >> ~/.hermes/.env
```

Merge `docs/hermes-config.yaml` into `~/.hermes/config.yaml` (adds the
`helpscout-tickets` route — read-only summarize, no drafting yet), then:

```bash
hermes gateway restart
```

### 3. Bring up the shim + smoke test the local chain

```bash
docker compose pull        # pulls the CI-built image from GHCR
docker compose up -d
docker compose logs -f hs-shim &
./smoke-test.sh
```

> If the GHCR package is private, run `docker login ghcr.io` (PAT with
> `read:packages`) before `pull`. To build locally instead of pulling, use
> `docker compose up -d --build`.

`200` → the full local chain works (shim verified SHA1 → re-signed SHA256 →
Hermes accepted → agent ran). See `smoke-test.sh` for what `401` / `502` mean.
Confirm a run fired for conversation `99999` in the gateway logs.

### 4. Expose + register (only after the local chain is 200)

Pick a public hostname (referred to below as `hs-hook.example.com` — substitute
your own). The shim itself never sees this name; it lives only in your ingress
config and the Help Scout registration.

- **HTTPS ingress** — expose the shim's loopback port to the public internet via
  any reverse proxy or tunnel (Cloudflare Tunnel, nginx, Caddy, …):
  `hs-hook.example.com` → `http://127.0.0.1:9100`. Do **not** layer additional
  auth (e.g. Cloudflare Access) on this route — Help Scout is unattended and
  can't authenticate; the SHA1 signature the shim verifies is the auth.
- **Help Scout webhook**: URL `https://hs-hook.example.com/hs`, secret =
  `HS_WEBHOOK_SECRET`, event `convo.created`.

Then create a real conversation and watch it flow end to end.

## Safety note

The first version is **read-only** (summarize, no writes). Before auto-firing the
agent on every ticket with writes enabled, confirm the Help Scout MCP namespace
exposes **no send/reply-and-send tool** (draft/note/status only). "Draft only" is
a real guarantee only once a draft can't become a sent email one tool-pick away.
