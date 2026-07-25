# Attestly — A2A white-glove verification service

An AI agent (or a human deploying agents) pays a small fee and a **real human** verifies
a fact or an entity, returned as a **cryptographically signed attestation** anyone can verify.

## The loop
1. Agent calls `POST /v1/verify` → `402 Payment Required` with x402 instructions.
2. Agent pays USDC, retries with header `X-PAYMENT: <payload>` → gets an `attestation_id` (pending).
3. **You** open `/admin`, verify by hand, click **Sign & publish** → the verdict is signed & public.
4. Anyone reads `/a/{id}` (page) or `/v1/attestations/{id}` (JSON) and can verify the signature.

## Run locally
```bash
pip install -r requirements.txt
cp .env.example .env          # fill in ADMIN_TOKEN + PAYTO_ADDRESS
set -a && . ./.env && set +a
uvicorn app:app --host 0.0.0.0 --port 8000
```
- Agent manifest: http://localhost:8000/
- Landing page:   http://localhost:8000/home
- Admin console:  http://localhost:8000/admin
- Health check:   http://localhost:8000/healthz

## Working jobs (the easy way)
Open `/admin`, paste your `ADMIN_TOKEN`, click **Load pending**. For each job: check the
sources, pick a verdict + confidence, write a one-line summary, add an evidence link, and
click **Sign & publish**. No command line needed.

## Payments
`check_payment()` runs in one of two modes (see `.env`):
- **Manual mode** (default): accepts a payment proof and flags the job `unverified_manual`.
  You reconcile the USDC on-chain before signing. Fine for a low-volume launch.
- **Facilitator mode**: set `FACILITATOR_URL` to a real x402 facilitator and
  `ALLOW_UNVERIFIED_PAYMENTS=false` — payments are verified automatically before a job is accepted.

## Deploy (Render, easiest)
1. Push this folder to a GitHub repo.
2. Render → **New + → Blueprint** → pick the repo (it reads `render.yaml`).
3. Set the secret env vars in the dashboard: `ADMIN_TOKEN`, `PAYTO_ADDRESS`, `BASE_URL`.
4. Add your custom domain in Render → point your DNS at it.
Docker and Procfile are included if you prefer Fly.io / Railway / any container host.

> The persistent disk in `render.yaml` keeps `attestly.db` and `signing_key.hex` across deploys.
> **Back up `signing_key.hex`** — it's the identity behind every signature.

## Stay out of regulation
Verify facts and entities only. No legal/medical/financial **advice**, no handling other
people's money, no KYC/identity proxying. Keep that line and you stay clear of licensed activity.

## Files
- `app.py` — the whole service (manifest, verify, admin console, landing, public pages)
- `requirements.txt`, `.env.example`, `.gitignore`, `.python-version`
- `Dockerfile`, `Procfile`, `render.yaml` — deploy configs
- `listing.md` — paste-ready marketplace listings
