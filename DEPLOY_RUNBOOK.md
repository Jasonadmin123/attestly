# Attestly — Go-Live Runbook (do these in order)

I've built and tested the whole service. These are the steps only you can do, because
they need your identity, your money, and your accounts. Total: a few hundred dollars
and roughly an afternoon. Do them top to bottom.

---

## Step 0 — What you already have (done for you)
A tested service: agent manifest, x402 payment gate, a browser **admin console** to work
jobs (no command line), ed25519-signed attestations, public verification pages, a human
landing page, and one-click deploy configs. All 15 self-tests pass.

---

## Step 1 — Domain  ✅ DONE
`attestly.co` is registered at Cloudflare. Every file in this kit is already set to it.
You'll point it at the app in Step 5.

## Step 2 — Create your USDC wallet on Base  (~15 min, free)
1. Install **Coinbase Wallet** (or any Base-compatible self-custody wallet).
2. Create a wallet. **Write down the recovery phrase on paper. Never type it into anything
   online, never share it, never put it in the code.**
3. Make sure it's set to the **Base** network and can receive **USDC**.
4. Copy your wallet's public address (starts with `0x…`). This is your `PAYTO_ADDRESS` —
   it's safe to share; it's just where payments arrive.

## Step 3 — Put the code on GitHub  (~15 min, free)
1. Create a free **GitHub** account if you don't have one.
2. Create a new **private** repo called `attestly`.
3. Upload the contents of the `attestly-starter` folder (drag-and-drop works in GitHub's
   web uploader). Make sure `.gitignore` is included so your `.env` and keys never upload.

## Step 4 — Pick your secrets  (~5 min)
- **ADMIN_TOKEN**: a long random string (e.g. run `openssl rand -hex 24`, or use a
  password manager). This is what logs you into the admin console — keep it private.
- **PAYTO_ADDRESS**: your `0x…` address from Step 2.
- **BASE_URL**: your domain, e.g. `https://attestly.co`.

## Step 5 — Deploy on Render  (~30–45 min, ~$0–7/mo)
1. Sign up at **render.com** and connect your GitHub.
2. **New + → Blueprint** → select your `attestly` repo. Render reads `render.yaml`.
3. When prompted, set the secret env vars: `ADMIN_TOKEN`, `PAYTO_ADDRESS`, `BASE_URL`.
4. Deploy. When it's live, open the Render URL + `/healthz` — you should see `{"ok":true}`.
5. **Custom domain**: Render → your service → Settings → Custom Domains → add
   `attestly.co`. Render shows a DNS record; add it at your registrar (Step 1).
   Wait for it to verify (minutes to an hour).

> The blueprint includes a persistent disk so your database and signing key survive
> deploys. **After first deploy, download/back up `signing_key.hex`** (via Render shell)
> and store it offline — it's the identity behind every signature.

## Step 6 — Smoke-test live  (~10 min)
- Visit `https://attestly.co/` → agent manifest (JSON).
- Visit `/home` → your landing page.
- Visit `/admin` → paste your ADMIN_TOKEN → **Load pending** (empty for now).
- Optional: send yourself a test job with curl (see README), then complete it in `/admin`
  and open its public `/a/{id}` page.

## Step 7 — List it  (~20 min, free)
1. Open `listing.md` — it's already set to `attestly.co`, ready to paste.
2. Post the **short version** in Moltbook `m/services` and `m/agentcommerce`.
3. Add it to any x402 service directory you can find.
4. Post the **human version** wherever operators who build agents hang out.

## Step 8 — Run the seed phase  (ongoing)
1. Temporarily lower the price: in `app.py`, set both services' `price_usd` to `2.00`
   (redeploy), or just honor a $1–3 intro rate manually. This is deliberate — you're
   buying your first reviews and signed track record.
2. When a job comes in, you'll reconcile the USDC payment by hand (manual mode), then
   verify and publish in `/admin`. Do every one fast and well.
3. After ~10–20 clean attestations, raise the price toward $8–15 and add premium tiers.

## Step 9 — Turn on automatic payments  (when volume justifies it)
Set `FACILITATOR_URL` to a real x402 facilitator and `ALLOW_UNVERIFIED_PAYMENTS=false`
in Render, then redeploy. Payments are then verified automatically before a job is
accepted. (Tell me when you're here — I'll wire it to your chosen facilitator and test it.)

---

## Safety lines (keep these and you stay unregulated)
- Verify **facts and entities only** — never legal/medical/financial **advice**.
- Never hold anyone's money (no escrow), never pass KYC or open accounts for others.
- Before real revenue, a 30-minute check with a lawyer on your setup is cheap insurance.

## When you get stuck
Tell me which step and what you see. I can walk you through Render, write the facilitator
integration, draft your first marketplace posts, or adjust the code — just say the word.
