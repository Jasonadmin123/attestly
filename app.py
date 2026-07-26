"""
Attestly — A2A white-glove verification & attestation service.

An AI agent (or a human deploying agents) pays a small fee and a REAL HUMAN verifies
a fact or an entity, returning a cryptographically signed attestation anyone can verify.

Endpoints
  GET  /                          agent-readable JSON manifest
  GET  /home                      human-facing landing page
  GET  /healthz                   health check (for hosting)
  GET  /.well-known/attestly-pubkey   the ed25519 public key
  POST /v1/verify                 request a verification (x402 paid)
  GET  /v1/attestations/{id}      read an attestation (JSON); ?canonical=1 for the signed payload
  GET  /a/{id}                    public attestation page (human + agent readable)
  GET  /admin                     browser console to work pending jobs (token-gated in the page)
  GET  /admin/pending             list pending jobs (needs X-ADMIN-TOKEN)
  POST /admin/attestations/{id}/complete   sign & publish a verdict (needs X-ADMIN-TOKEN)

Run:
  cp .env.example .env   # fill it in
  set -a && . ./.env && set +a
  uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os
import re
import ssl
import socket
import json
import hashlib
import sqlite3
import secrets
from datetime import datetime, timezone
from contextlib import closing

import httpx
import whois
import dns.resolver
from fastmcp import FastMCP
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
BRAND          = "Attestly"
DB_PATH        = os.environ.get("ATTESTLY_DB", "attestly.db")
KEY_PATH       = os.environ.get("ATTESTLY_KEY", "signing_key.hex")
ADMIN_TOKEN    = os.environ.get("ADMIN_TOKEN", "change-me")
PAYTO_ADDRESS  = os.environ.get("PAYTO_ADDRESS", "0xYOUR_WALLET_ADDRESS")
PAY_NETWORK    = os.environ.get("PAY_NETWORK", "base")
PAY_ASSET      = os.environ.get("PAY_ASSET", "USDC")
BASE_URL       = os.environ.get("BASE_URL", "http://localhost:8000")
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "").rstrip("/")   # e.g. https://x402.org/facilitator
ALLOW_UNVERIFIED = os.environ.get("ALLOW_UNVERIFIED_PAYMENTS", "true").lower() == "true"
CONTACT_EMAIL  = os.environ.get("CONTACT_EMAIL", "you@yourdomain.com")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")             # email alerts on new jobs
ALERT_EMAIL    = os.environ.get("ALERT_EMAIL", "jason@theleadforge.com")
ALERT_FROM     = os.environ.get("ALERT_FROM", "Attestly <onboarding@resend.dev>")
BASESCAN_API_KEY = os.environ.get("BASESCAN_API_KEY", "")          # optional: wallet age signal

# Automated-check config. Each network has a list of public RPC endpoints tried in
# order — if one blocks/rate-limits, the next is tried. Override the first with env.
RPC_URLS = {
    "base": [os.environ.get("BASE_RPC_URL", "https://mainnet.base.org"),
             "https://base.llamarpc.com", "https://base-rpc.publicnode.com",
             "https://base.drpc.org"],
    "ethereum": [os.environ.get("ETH_RPC_URL", "https://eth.llamarpc.com"),
                 "https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com",
                 "https://eth.drpc.org"],
}
# Blockscout explorers — free, keyless. Used for the wallet "age / first-tx" signal.
BLOCKSCOUT_URLS = {
    "base": os.environ.get("BASE_BLOCKSCOUT_URL", "https://base.blockscout.com"),
    "ethereum": os.environ.get("ETH_BLOCKSCOUT_URL", "https://eth.blockscout.com"),
}
OFAC_LIST_URL = os.environ.get(
    "OFAC_LIST_URL",
    "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt",
)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "throwawaymail.com", "getnada.com", "trashmail.com",
    "sharklasers.com", "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com",
    "mohmal.com", "emailondeck.com", "spam4.me", "grr.la", "guerrillamailblock.com",
}
_OFAC_CACHE = {"addrs": set(), "fetched_at": None}

SERVICES = {
    "entity_check": {
        "title": "Human-verified entity check",
        "description": "A real human confirms whether a business/entity exists and matches the details you provide, with evidence and a signed verdict.",
        "price_usd": 4.00,
    },
    "claim_check": {
        "title": "Human-verified claim check",
        "description": "A real human checks a factual claim or URL against real sources and returns confirmed / refuted / uncertain, with evidence and a signed verdict.",
        "price_usd": 4.00,
    },
    "notarize": {
        "title": "Content notarization (signed timestamp)",
        "description": "Submit content or a SHA-256 hash; get an instant ed25519-signed proof it existed at this time.",
        "price_usd": 0.50, "auto": True,
    },
    "domain_check": {
        "title": "Domain & website verification",
        "description": "Instant automated check: does the domain resolve, is TLS valid, how old is it, registrar, reachability.",
        "price_usd": 0.50, "auto": True,
    },
    "email_check": {
        "title": "Email verification",
        "description": "Instant automated check: syntax, MX records, disposable-domain detection, deliverability signal.",
        "price_usd": 0.50, "auto": True,
    },
    "wallet_screen": {
        "title": "Crypto wallet risk & sanctions screening",
        "description": "Instant automated screen of an EVM address against OFAC sanctions + on-chain activity. Know your counterparty before you pay.",
        "price_usd": 1.00, "auto": True,
    },
}

# ----------------------------------------------------------------------------
# Signing key
# ----------------------------------------------------------------------------
def load_or_create_key() -> SigningKey:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH) as f:
            return SigningKey(f.read().strip(), encoder=HexEncoder)
    key = SigningKey.generate()
    with open(KEY_PATH, "w") as f:
        f.write(key.encode(encoder=HexEncoder).decode())
    return key

SIGNING_KEY = load_or_create_key()
PUBLIC_KEY_HEX = SIGNING_KEY.verify_key.encode(encoder=HexEncoder).decode()

# ----------------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attestations (
                id TEXT PRIMARY KEY, service TEXT NOT NULL, subject TEXT NOT NULL,
                status TEXT NOT NULL, verdict TEXT, summary TEXT, evidence TEXT,
                confidence INTEGER, payment_ref TEXT, payment_status TEXT,
                created_at TEXT NOT NULL, completed_at TEXT, issuer TEXT, signature TEXT
            )""")
        conn.commit()
init_db()

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def canonical_payload(row) -> str:
    payload = {
        "id": row["id"], "service": row["service"], "subject": json.loads(row["subject"]),
        "verdict": row["verdict"], "summary": row["summary"],
        "evidence": json.loads(row["evidence"] or "[]"), "confidence": row["confidence"],
        "issued_at": row["completed_at"], "issuer": row["issuer"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))

# ----------------------------------------------------------------------------
# Payment (x402)
# ----------------------------------------------------------------------------
def x402_challenge(service_key: str) -> JSONResponse:
    svc = SERVICES[service_key]
    return JSONResponse(status_code=402, content={
        "x402Version": 1, "error": "payment_required",
        "accepts": [{
            "scheme": "exact", "network": PAY_NETWORK, "asset": PAY_ASSET,
            "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS,
            "resource": f"{BASE_URL}/v1/verify", "description": svc["title"],
            "mimeType": "application/json",
        }],
        "note": "Pay the amount above in USDC, then retry with header 'X-PAYMENT: <payload>'.",
    })

def check_payment(proof: str | None, service_key: str) -> tuple[bool, str]:
    """
    Returns (accepted, payment_status).
    - If FACILITATOR_URL is set, verify the payment for real via the x402 facilitator.
    - Else if ALLOW_UNVERIFIED_PAYMENTS, accept a non-empty proof but flag it so YOU
      reconcile the on-chain payment before signing. (Fine for low-volume manual launch.)
    - Else reject (safe default in production without a facilitator).
    """
    if not proof:
        return (False, "none")
    if FACILITATOR_URL:
        svc = SERVICES[service_key]
        requirements = {
            "scheme": "exact", "network": PAY_NETWORK, "asset": PAY_ASSET,
            "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS,
            "resource": f"{BASE_URL}/v1/verify",
        }
        try:
            r = httpx.post(f"{FACILITATOR_URL}/verify",
                           json={"x402Version": 1, "paymentPayload": proof, "paymentRequirements": requirements},
                           timeout=15)
            ok = r.status_code == 200 and r.json().get("isValid", r.json().get("valid", False))
            return (bool(ok), "verified" if ok else "rejected")
        except Exception:
            return (False, "facilitator_error")
    if ALLOW_UNVERIFIED:
        return (True, "unverified_manual")
    return (False, "no_facilitator")

# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------
def notify_new_job(att_id: str, service: str) -> None:
    """Fire-and-forget email alert via Resend. Never breaks the request if email fails."""
    if not RESEND_API_KEY:
        return
    try:
        httpx.post("https://api.resend.com/emails",
                   headers={"Authorization": "Bearer " + RESEND_API_KEY, "Content-Type": "application/json"},
                   json={"from": ALERT_FROM, "to": [ALERT_EMAIL],
                         "subject": f"Attestly 💰 new {service} job",
                         "text": f"You have a new {service} request.\n\n"
                                 f"Job id: {att_id}\n\n"
                                 f"Next step: open {BASE_URL}/admin, verify it against sources, then Sign & publish.\n"
                                 f"(Confirm the USDC landed in your wallet first.)"},
                   timeout=8)
    except Exception:
        pass

# ----------------------------------------------------------------------------
# Automated checks (no human) — run synchronously, sign, return completed.
# ----------------------------------------------------------------------------
def finalize_auto(service: str, subject: dict, verdict: str, confidence: int,
                  summary: str, evidence=None, data=None) -> dict:
    """Create an already-completed, signed attestation for an automated check."""
    evidence = evidence or []
    att_id = "at_" + secrets.token_hex(8)
    now = now_iso()
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO attestations (id,service,subject,status,verdict,summary,evidence,confidence,payment_status,created_at,completed_at,issuer) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (att_id, service, json.dumps(subject), "completed", verdict, summary,
             json.dumps(evidence), confidence, "auto", now, now, "Attestly automated check"))
        conn.commit()
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
        sig = SIGNING_KEY.sign(canonical_payload(row).encode(), encoder=HexEncoder).signature.decode()
        conn.execute("UPDATE attestations SET signature=? WHERE id=?", (sig, att_id))
        conn.commit()
    return {"attestation_id": att_id, "status": "completed", "verdict": verdict,
            "confidence": confidence, "summary": summary, "evidence": evidence,
            "data": data or {}, "signature": sig, "public_key": PUBLIC_KEY_HEX,
            "public_url": f"{BASE_URL}/a/{att_id}"}

def _ofac_addresses() -> set:
    """Fetch + cache the OFAC sanctioned crypto address list (daily). Fails safe to cached/empty."""
    from datetime import date
    if _OFAC_CACHE["fetched_at"] == str(date.today()) and _OFAC_CACHE["addrs"]:
        return _OFAC_CACHE["addrs"]
    try:
        r = httpx.get(OFAC_LIST_URL, timeout=10)
        if r.status_code == 200:
            addrs = {ln.strip().lower() for ln in r.text.splitlines() if ln.strip().startswith("0x")}
            if addrs:
                _OFAC_CACHE["addrs"] = addrs
                _OFAC_CACHE["fetched_at"] = str(date.today())
    except Exception:
        pass
    return _OFAC_CACHE["addrs"]

def run_notarize(subject: dict):
    content = subject.get("content")
    sha = (subject.get("sha256") or "").lower().strip()
    if content:
        sha = hashlib.sha256(str(content).encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        raise ValueError("provide 'content' to hash, or a valid 64-char hex 'sha256'")
    summary = f"SHA-256 {sha[:16]}… notarized — existence attested at {now_iso()}."
    return ("notarized", 100, summary, [{"label": "sha256", "note": sha}],
            {"sha256": sha}, {"sha256": sha})   # store only the hash, never raw content

def run_domain_check(subject: dict):
    domain = (subject.get("domain") or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
    if not domain or "." not in domain:
        raise ValueError("provide a 'domain', e.g. example.com")
    resolves = mx = ssl_valid = False
    age_days = created = registrar = ssl_issuer = ssl_expires = http_status = None
    try:
        dns.resolver.resolve(domain, "A", lifetime=5); resolves = True
    except Exception: pass
    try:
        dns.resolver.resolve(domain, "MX", lifetime=5); mx = True
    except Exception: pass
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0] if cd else None
        if cd and hasattr(cd, "year"):
            created = str(cd)
            try: age_days = (datetime.now() - cd.replace(tzinfo=None)).days
            except Exception: age_days = None
        registrar = str(w.registrar) if getattr(w, "registrar", None) else None
    except Exception: pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ss:
                cert = ss.getpeercert(); ssl_valid = True
                ssl_expires = cert.get("notAfter")
                ssl_issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName")
    except Exception: pass
    for scheme in ("https", "http"):
        try:
            http_status = httpx.get(f"{scheme}://{domain}", timeout=6, follow_redirects=True).status_code
            break
        except Exception: pass
    signals = sum([resolves, ssl_valid, bool(http_status and http_status < 500)])
    if not resolves:
        verdict, conf = "refuted", 90
    elif signals >= 3:
        verdict, conf = "confirmed", 90
    else:
        verdict, conf = "uncertain", 60
    summary = (f"{domain}: resolves={resolves}, TLS={'valid' if ssl_valid else 'no/invalid'}, "
               f"HTTP={http_status}, age={age_days}d, registrar={registrar}.")
    data = {"domain": domain, "resolves": resolves, "mx_found": mx, "age_days": age_days,
            "created": created, "registrar": registrar, "ssl_valid": ssl_valid,
            "ssl_issuer": ssl_issuer, "ssl_expires": ssl_expires, "http_status": http_status}
    evidence = [{"label": "dns", "note": f"A={resolves}, MX={mx}"},
                {"label": "tls", "note": f"valid={ssl_valid}, issuer={ssl_issuer}, expires={ssl_expires}"},
                {"label": "whois", "note": f"created={created}, registrar={registrar}"},
                {"label": "http", "note": f"status={http_status}"}]
    return (verdict, conf, summary, evidence, data, {"domain": domain})

def run_email_check(subject: dict):
    email = (subject.get("email") or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return ("refuted", 95, f"'{email}' is not a valid email address.",
                [{"label": "syntax", "note": "invalid"}],
                {"email": email, "syntax_valid": False}, {"email": email})
    domain = email.split("@")[1].lower()
    mx = False
    try:
        mx = len(dns.resolver.resolve(domain, "MX", lifetime=5)) > 0
    except Exception: pass
    disposable = domain in DISPOSABLE_DOMAINS
    if not mx:
        verdict, conf, guess = "refuted", 85, "undeliverable (no MX records)"
    elif disposable:
        verdict, conf, guess = "uncertain", 70, "disposable/temporary address"
    else:
        verdict, conf, guess = "confirmed", 80, "likely deliverable"
    summary = f"{email}: syntax ok, MX={'found' if mx else 'none'}, disposable={disposable} → {guess}."
    data = {"email": email, "syntax_valid": True, "domain": domain, "mx_found": mx,
            "disposable": disposable, "deliverable_guess": guess}
    evidence = [{"label": "mx", "note": str(mx)}, {"label": "disposable", "note": str(disposable)}]
    return (verdict, conf, summary, evidence, data, {"email": email})

def _wallet_age(addr: str, network: str):
    """First-transaction date + age in days via Blockscout (free, keyless). (age_days, first_tx_iso) or (None, None)."""
    base = BLOCKSCOUT_URLS.get(network, BLOCKSCOUT_URLS["base"])
    try:
        r = httpx.get(f"{base}/api", params={"module": "account", "action": "txlist",
                      "address": addr, "sort": "asc", "page": 1, "offset": 1}, timeout=10)
        j = r.json()
        res = j.get("result")
        if j.get("status") == "1" and isinstance(res, list) and res:
            ts = int(res[0]["timeStamp"])
            first = datetime.utcfromtimestamp(ts)
            return ((datetime.utcnow() - first).days, first.isoformat() + "Z")
    except Exception:
        pass
    return (None, None)

def run_wallet_screen(subject: dict):
    addr = (subject.get("address") or "").strip()
    network = (subject.get("network") or "base").lower()
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        raise ValueError("provide a valid EVM 'address' (0x + 40 hex chars)")
    sanctioned = addr.lower() in _ofac_addresses()
    balance = tx_count = None
    endpoints = RPC_URLS.get(network, RPC_URLS["base"])
    for rpc in endpoints:
        try:
            bal = httpx.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                                        "params": [addr, "latest"]}, timeout=8).json().get("result")
            nc = httpx.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount",
                                       "params": [addr, "latest"]}, timeout=8).json().get("result")
            if bal is not None or nc is not None:
                if bal is not None: balance = int(bal, 16) / 1e18
                if nc is not None: tx_count = int(nc, 16)
                break   # got a working endpoint
        except Exception:
            continue
    age_days, first_tx = _wallet_age(addr, network)
    flags = []
    if sanctioned:
        verdict, conf, risk = "refuted", 99, "high"; flags.append("OFAC-sanctioned")
    elif tx_count is None and age_days is None:
        verdict, conf, risk = "uncertain", 50, "unknown"; flags.append("could not read chain")
    elif (tx_count == 0) or (age_days == 0 and not tx_count):
        verdict, conf, risk = "uncertain", 70, "medium"; flags.append("no on-chain history")
    else:
        verdict, conf, risk = "confirmed", 80, "low"
    # Age enrichment: a very fresh address is a mild risk signal even if it has activity.
    if age_days is not None:
        if age_days < 7 and risk == "low":
            risk, conf = "medium", 70; flags.append("very new address (<7d)")
        elif age_days < 30 and risk == "low":
            flags.append("new address (<30d)")
        elif age_days >= 365 and risk == "low":
            conf = 88; flags.append("established (1y+)")
    summary = (f"{addr} ({network}): sanctioned={sanctioned}, balance={balance}, "
               f"tx_count={tx_count}, age={age_days}d → risk {risk}.")
    data = {"address": addr, "network": network, "sanctioned": sanctioned,
            "sanctions_source": "OFAC SDN crypto list", "sanctions_snapshot": _OFAC_CACHE.get("fetched_at"),
            "balance": balance, "tx_count": tx_count, "age_days": age_days, "first_tx": first_tx,
            "risk_level": risk, "flags": flags}
    evidence = [{"label": "sanctions", "note": f"OFAC match={sanctioned}"},
                {"label": "onchain", "note": f"balance={balance}, tx_count={tx_count}"},
                {"label": "age", "note": f"first_tx={first_tx}, age_days={age_days}"}]
    return (verdict, conf, summary, evidence, data, {"address": addr, "network": network})

AUTO_RUNNERS = {
    "notarize": run_notarize,
    "domain_check": run_domain_check,
    "email_check": run_email_check,
    "wallet_screen": run_wallet_screen,
}

def run_auto(service: str, subject: dict) -> dict:
    """Run an automated check and return a signed, completed attestation."""
    verdict, conf, summary, evidence, data, stored_subject = AUTO_RUNNERS[service](subject)
    return finalize_auto(service, stored_subject, verdict, conf, summary, evidence, data)

# ----------------------------------------------------------------------------
# Hosted MCP server (remote, callable at /mcp) — so any MCP agent can use Attestly
# by URL, no install. Tools reuse the internal logic below.
# ----------------------------------------------------------------------------
_mcp = FastMCP("Attestly")

@_mcp.tool
def get_services() -> dict:
    """List Attestly's verification services, prices (USDC), and how payment works."""
    return {"services": SERVICES,
            "payment": {"protocol": "x402", "network": PAY_NETWORK, "asset": PAY_ASSET, "pay_to": PAYTO_ADDRESS}}

@_mcp.tool
def request_verification(service: str, subject: dict, payment: str = "") -> dict:
    """Ask a real human to verify a fact or an entity, returned as a signed attestation.
    service: 'entity_check' (does this business/entity exist & match?) or 'claim_check' (is this claim/URL true?).
    subject: what to verify, e.g. {"business":"Acme LLC","state":"AZ","claim":"is registered"}.
    payment: your x402 payment proof. Omit to first receive payment requirements, then pay and call again."""
    if service not in SERVICES:
        return {"error": f"unknown service '{service}'. Use get_services()."}
    accepted, pay_status = check_payment(payment or None, service)
    if not accepted:
        svc = SERVICES[service]
        return {"payment_required": {"protocol": "x402", "network": PAY_NETWORK, "asset": PAY_ASSET,
                                     "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS},
                "note": "Pay the amount in USDC, then call request_verification again with the payment proof."}
    att_id = "at_" + secrets.token_hex(8)
    with closing(db()) as conn:
        conn.execute("INSERT INTO attestations (id,service,subject,status,payment_ref,payment_status,created_at) VALUES (?,?,?,?,?,?,?)",
                     (att_id, service, json.dumps(subject), "pending", (payment or "")[:80], pay_status, now_iso()))
        conn.commit()
    notify_new_job(att_id, service)
    return {"attestation_id": att_id, "status": "pending",
            "status_url": f"{BASE_URL}/v1/attestations/{att_id}", "public_url": f"{BASE_URL}/a/{att_id}"}

@_mcp.tool
def get_attestation(attestation_id: str) -> dict:
    """Fetch an attestation by id: status, and (when completed) the signed verdict, evidence,
    confidence, signature, and public key so you can verify it yourself."""
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (attestation_id,)).fetchone()
    if not row:
        return {"error": "not found"}
    out = {"id": row["id"], "service": row["service"], "subject": json.loads(row["subject"]),
           "status": row["status"], "created_at": row["created_at"]}
    if row["status"] == "completed":
        out.update({"verdict": row["verdict"], "summary": row["summary"],
                    "evidence": json.loads(row["evidence"] or "[]"), "confidence": row["confidence"],
                    "issued_at": row["completed_at"], "issuer": row["issuer"],
                    "signature": row["signature"], "public_key": PUBLIC_KEY_HEX})
    return out

def _auto_tool(service: str, subject: dict, payment: str):
    """Shared body for the automated MCP tools: gate on payment, run, return signed result."""
    accepted, _ = check_payment(payment or None, service)
    if not accepted:
        svc = SERVICES[service]
        return {"payment_required": {"protocol": "x402", "network": PAY_NETWORK, "asset": PAY_ASSET,
                                     "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS},
                "note": f"Pay {svc['price_usd']:.2f} USDC, then call again with the payment proof. Instant, signed result on payment."}
    try:
        return run_auto(service, subject)
    except ValueError as e:
        return {"error": str(e)}

@_mcp.tool
def notarize(content: str = "", sha256: str = "", payment: str = "") -> dict:
    """Instantly notarize content: get an ed25519-signed proof it existed at this time. 0.50 USDC.
    Provide 'content' to hash (only the hash is stored, never the raw content), or a 64-char hex 'sha256'.
    payment: your x402 proof. Omit to receive payment requirements first. Proves existence at time T, not authorship."""
    return _auto_tool("notarize", {"content": content, "sha256": sha256}, payment)

@_mcp.tool
def domain_check(domain: str, payment: str = "") -> dict:
    """Instantly verify a domain/website: does it resolve, is TLS valid, how old, registrar, reachable. 0.50 USDC.
    Returns a signed verdict (confirmed/refuted/uncertain) with evidence. payment: your x402 proof; omit to get requirements first.
    Informational — 'resolves + valid cert' is not proof the business is trustworthy."""
    return _auto_tool("domain_check", {"domain": domain}, payment)

@_mcp.tool
def email_check(email: str, payment: str = "") -> dict:
    """Instantly verify an email address: syntax, MX records, disposable-domain detection, deliverability signal. 0.50 USDC.
    Returns a signed verdict with evidence. payment: your x402 proof; omit to get requirements first.
    Deliverability is best-effort; a 'valid' result is not a guarantee of inbox delivery."""
    return _auto_tool("email_check", {"email": email}, payment)

@_mcp.tool
def wallet_screen(address: str, network: str = "base", payment: str = "") -> dict:
    """Instantly screen an EVM address against OFAC sanctions + on-chain activity before you pay a counterparty. 1.00 USDC.
    Returns a signed verdict with risk level and evidence. network: 'base' or 'ethereum'. payment: your x402 proof; omit to get requirements first.
    Informational screening only — NOT compliance, legal, or financial advice, and not 'KYC-certified'."""
    return _auto_tool("wallet_screen", {"address": address, "network": network}, payment)

_mcp_app = _mcp.http_app(path="/mcp")   # internal route is exactly /mcp (no trailing-slash redirect)

app = FastAPI(title=BRAND, version="0.2.0", lifespan=_mcp_app.lifespan)
# Attach the MCP route(s) directly (instead of app.mount) so /mcp works without a redirect.
for _r in _mcp_app.routes:
    app.router.routes.append(_r)

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": BRAND}

@app.get("/")
def manifest():
    return {
        "name": BRAND, "type": "a2a-verification-service",
        "summary": "The trust layer for AI agents: instant automated checks (wallet/sanctions, domain, email, notarization) plus human-verified attestations — all cryptographically signed (ed25519). Pay per check in USDC via x402.",
        "public_key": PUBLIC_KEY_HEX,
        "verify_signature": "ed25519 over the canonical JSON at /v1/attestations/{id}?canonical=1",
        "payment": {"protocol": "x402", "network": PAY_NETWORK, "asset": PAY_ASSET, "pay_to": PAYTO_ADDRESS},
        "services": {k: {"title": v["title"], "description": v["description"], "price_usd": v["price_usd"]}
                     for k, v in SERVICES.items()},
        "how_to_use": {
            "1_request": f"POST {BASE_URL}/v1/verify  body: {{\"service\":\"entity_check\",\"subject\":{{...}}}}",
            "2_pay": "Receive HTTP 402 with payment requirements. Pay, then retry with header X-PAYMENT.",
            "3_poll": f"GET {BASE_URL}/v1/attestations/{{id}} until status == completed",
            "4_verify": "Verify the ed25519 signature against public_key using the canonical payload",
        },
    }

@app.get("/.well-known/attestly-pubkey")
def pubkey():
    return {"algo": "ed25519", "public_key_hex": PUBLIC_KEY_HEX}

def _agent_card():
    return {
        "protocolVersion": "0.3.0",
        "name": BRAND,
        "description": "The trust layer for AI agents. Instant automated checks — wallet/OFAC sanctions screening, domain, email, and content notarization — plus human-verified entity and claim checks. Every result is a cryptographically signed (ed25519) attestation. Pay per check in USDC via x402.",
        "url": BASE_URL,
        "preferredTransport": "JSONRPC",
        "version": "0.2.0",
        "provider": {"organization": BRAND, "url": BASE_URL},
        "documentationUrl": f"{BASE_URL}/",
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": False},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {"id": "entity-check", "name": "Human-verified entity check",
             "description": "A real human confirms whether a business/entity exists and matches the details provided; returns a signed verdict with evidence. Price: %.2f USDC." % SERVICES["entity_check"]["price_usd"],
             "tags": ["verification", "kyb", "entity", "trust", "x402"],
             "examples": ["Is 'Acme Lending LLC' a registered active business in Arizona?"]},
            {"id": "claim-check", "name": "Human-verified claim check",
             "description": "A real human checks a factual claim or URL against real sources; returns confirmed/refuted/uncertain with evidence. Price: %.2f USDC." % SERVICES["claim_check"]["price_usd"],
             "tags": ["verification", "fact-check", "trust", "x402"],
             "examples": ["Verify: 'https://example.com is the official site of Example Corp.'"]},
            {"id": "wallet-screen", "name": "Wallet risk & sanctions screening (instant)",
             "description": "Instantly screen an EVM address against OFAC sanctions + on-chain activity; returns a signed risk verdict. Informational, not compliance advice. Price: %.2f USDC." % SERVICES["wallet_screen"]["price_usd"],
             "tags": ["verification", "wallet", "sanctions", "ofac", "risk", "x402", "instant"],
             "examples": ["Screen 0x1234...abcd on base before I send USDC."]},
            {"id": "domain-check", "name": "Domain & website verification (instant)",
             "description": "Instantly check whether a domain resolves, has valid TLS, its age and registrar, and reachability; returns a signed verdict. Price: %.2f USDC." % SERVICES["domain_check"]["price_usd"],
             "tags": ["verification", "domain", "website", "tls", "x402", "instant"],
             "examples": ["Is stripe.com a real, resolving site with valid TLS?"]},
            {"id": "email-check", "name": "Email verification (instant)",
             "description": "Instantly check an email's syntax, MX records, disposable-domain status, and deliverability signal; returns a signed verdict. Price: %.2f USDC." % SERVICES["email_check"]["price_usd"],
             "tags": ["verification", "email", "deliverability", "x402", "instant"],
             "examples": ["Is user@example.com a deliverable, non-disposable address?"]},
            {"id": "notarize", "name": "Content notarization (instant)",
             "description": "Instantly notarize content or a hash — an ed25519-signed proof it existed at time T. Proves existence, not authorship. Price: %.2f USDC." % SERVICES["notarize"]["price_usd"],
             "tags": ["notary", "timestamp", "hash", "proof", "x402", "instant"],
             "examples": ["Notarize the SHA-256 of this agreement text."]},
        ],
    }

@app.get("/.well-known/agent.json")
@app.get("/.well-known/agent-card.json")
def agent_card():
    return _agent_card()

@app.get("/llms.txt", response_class=PlainTextResponse)
def llms_txt():
    return f"""# {BRAND}

> The trust layer for AI agents. Instant automated checks plus human-verified attestations, all cryptographically signed (ed25519). Pay per check in USDC via the x402 protocol. Verdicts: confirmed / refuted / uncertain, with evidence and a confidence score.

## Instant automated checks (signed result in the same response)
- wallet_screen (${SERVICES['wallet_screen']['price_usd']:.2f} USDC): screen an EVM address vs OFAC sanctions + on-chain activity before you pay a counterparty. Informational, not compliance advice.
- domain_check (${SERVICES['domain_check']['price_usd']:.2f} USDC): does a domain resolve, valid TLS, age, registrar, reachability.
- email_check (${SERVICES['email_check']['price_usd']:.2f} USDC): syntax, MX records, disposable-domain detection, deliverability signal.
- notarize (${SERVICES['notarize']['price_usd']:.2f} USDC): signed proof that content (or its hash) existed at time T. Existence, not authorship.

## Human-verified checks (reviewed by a real person, usually within hours)
- entity_check (${SERVICES['entity_check']['price_usd']:.0f} USDC): confirm a business/entity exists and matches given details.
- claim_check (${SERVICES['claim_check']['price_usd']:.0f} USDC): check a factual claim or URL against real sources.

## How an agent uses it
1. POST {BASE_URL}/v1/verify  body: {{"service":"wallet_screen","subject":{{"address":"0x..."}}}}
2. Receive HTTP 402 with x402 payment requirements. Pay in USDC, retry with header X-PAYMENT.
3. Automated services return the signed, completed attestation immediately. Human services return a job id — poll GET {BASE_URL}/v1/attestations/{{id}} until status == completed.
4. Verify the ed25519 signature against the public key in the manifest.
Or call the hosted MCP server at {BASE_URL}/mcp (tools: wallet_screen, domain_check, email_check, notarize, request_verification, get_attestation, get_services).

## Links
- Manifest (JSON): {BASE_URL}/
- Agent card (A2A): {BASE_URL}/.well-known/agent.json
- Public key: {BASE_URL}/.well-known/attestly-pubkey
- Human overview: {BASE_URL}/home
"""

# ---- Paid verification request ----
class VerifyRequest(BaseModel):
    service: str = Field(..., description="e.g. 'entity_check'")
    subject: dict = Field(..., description="What to verify, e.g. {'business':'Acme LLC','state':'AZ','claim':'is registered'}")

@app.post("/v1/verify")
def verify(req: VerifyRequest, x_payment: str | None = Header(default=None)):
    if req.service not in SERVICES:
        raise HTTPException(400, f"unknown service '{req.service}'. See GET / for options.")
    accepted, pay_status = check_payment(x_payment, req.service)
    if not accepted:
        return x402_challenge(req.service)
    # Automated services run synchronously and return a signed, completed attestation now.
    if SERVICES[req.service].get("auto"):
        try:
            return run_auto(req.service, req.subject)
        except ValueError as e:
            raise HTTPException(400, str(e))
    att_id = "at_" + secrets.token_hex(8)
    with closing(db()) as conn:
        conn.execute("INSERT INTO attestations (id,service,subject,status,payment_ref,payment_status,created_at) VALUES (?,?,?,?,?,?,?)",
                     (att_id, req.service, json.dumps(req.subject), "pending",
                      (x_payment or "")[:80], pay_status, now_iso()))
        conn.commit()
    notify_new_job(att_id, req.service)
    return {"attestation_id": att_id, "status": "pending", "payment_status": pay_status,
            "status_url": f"{BASE_URL}/v1/attestations/{att_id}",
            "public_url": f"{BASE_URL}/a/{att_id}",
            "expected_turnaround": "usually within a few hours (white-glove, human-reviewed)"}

@app.get("/v1/attestations/{att_id}")
def get_attestation(att_id: str, canonical: int = 0):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    if canonical and row["status"] == "completed":
        return JSONResponse(content=json.loads(canonical_payload(row)))
    out = {"id": row["id"], "service": row["service"], "subject": json.loads(row["subject"]),
           "status": row["status"], "created_at": row["created_at"]}
    if row["status"] == "completed":
        out.update({"verdict": row["verdict"], "summary": row["summary"],
                    "evidence": json.loads(row["evidence"] or "[]"), "confidence": row["confidence"],
                    "issued_at": row["completed_at"], "issuer": row["issuer"],
                    "signature": row["signature"], "public_key": PUBLIC_KEY_HEX})
    return out

# ---- Fulfillment ----
class CompleteRequest(BaseModel):
    verdict: str
    summary: str
    evidence: list[dict] = Field(default_factory=list)
    confidence: int = Field(..., ge=0, le=100)
    issuer: str = Field(default="Attestly human reviewer")

def require_admin(token: str | None):
    if token != ADMIN_TOKEN:
        raise HTTPException(401, "bad admin token")

@app.get("/admin/stats")
def admin_stats(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with closing(db()) as conn:
        rows = conn.execute("SELECT service, status, payment_status FROM attestations").fetchall()
    total = len(rows)
    pending = sum(1 for r in rows if r["status"] == "pending")
    completed = sum(1 for r in rows if r["status"] == "completed")
    # Real revenue = completed jobs whose payment was actually verified on-chain.
    verified_revenue = round(sum(SERVICES.get(r["service"], {}).get("price_usd", 0)
                                 for r in rows if r["status"] == "completed"
                                 and r["payment_status"] == "verified"), 2)
    # Gross = every completed check regardless of payment (includes test/unverified/auto).
    gross = round(sum(SERVICES.get(r["service"], {}).get("price_usd", 0)
                      for r in rows if r["status"] == "completed"), 2)
    by_service = {}
    for r in rows:
        by_service[r["service"]] = by_service.get(r["service"], 0) + 1
    return {"total_jobs": total, "pending": pending, "completed": completed,
            "revenue_usd": verified_revenue, "gross_completed_usd": gross,
            "by_service": by_service}

@app.get("/admin/pending")
def admin_pending(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with closing(db()) as conn:
        rows = conn.execute("SELECT id,service,subject,payment_status,created_at FROM attestations WHERE status='pending' ORDER BY created_at").fetchall()
    return [{"id": r["id"], "service": r["service"], "subject": json.loads(r["subject"]),
             "payment_status": r["payment_status"], "created_at": r["created_at"]} for r in rows]

@app.get("/admin/jobs")
def admin_jobs(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with closing(db()) as conn:
        rows = conn.execute("SELECT * FROM attestations ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        svc = SERVICES.get(r["service"], {})
        out.append({
            "id": r["id"], "service": r["service"], "auto": bool(svc.get("auto")),
            "subject": json.loads(r["subject"]), "status": r["status"],
            "verdict": r["verdict"], "summary": r["summary"], "confidence": r["confidence"],
            "evidence": json.loads(r["evidence"] or "[]"),
            "payment_ref": r["payment_ref"], "payment_status": r["payment_status"],
            "price_usd": svc.get("price_usd", 0), "issuer": r["issuer"],
            "created_at": r["created_at"], "completed_at": r["completed_at"],
            "signature": r["signature"], "public_url": f"{BASE_URL}/a/{r['id']}",
        })
    return out

@app.post("/admin/attestations/{att_id}/complete")
def complete(att_id: str, body: CompleteRequest, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    if body.verdict not in ("confirmed", "refuted", "uncertain"):
        raise HTTPException(400, "verdict must be confirmed|refuted|uncertain")
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
        if not row:
            raise HTTPException(404, "not found")
        completed_at = now_iso()
        conn.execute("UPDATE attestations SET verdict=?,summary=?,evidence=?,confidence=?,issuer=?,completed_at=?,status=? WHERE id=?",
                     (body.verdict, body.summary, json.dumps(body.evidence), body.confidence,
                      body.issuer, completed_at, "completed", att_id))
        conn.commit()
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
        signature = SIGNING_KEY.sign(canonical_payload(row).encode(), encoder=HexEncoder).signature.decode()
        conn.execute("UPDATE attestations SET signature=? WHERE id=?", (signature, att_id))
        conn.commit()
    return {"ok": True, "attestation_id": att_id, "public_url": f"{BASE_URL}/a/{att_id}", "signature": signature}

# ---- Public attestation page ----
@app.get("/a/{att_id}", response_class=HTMLResponse)
def public_page(att_id: str):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
    if not row:
        return HTMLResponse("<h1>Attestation not found</h1>", status_code=404)
    if row["status"] != "completed":
        return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>{att_id}</title>
        <body style="font-family:system-ui;max-width:640px;margin:60px auto;color:#222">
        <h1>{BRAND} attestation {att_id}</h1><p><b>Status:</b> pending human review.</p>
        <p>Requested: {json.dumps(json.loads(row['subject']))}</p></body>""")
    evidence = json.loads(row["evidence"] or "[]")
    def ev_line(e):
        url = e.get("url"); link = f'<a href="{url}">{url}</a>' if url else ""
        return f"<li>{e.get('label','')} — {link} {e.get('note','')}</li>"
    ev_html = "".join(ev_line(e) for e in evidence) or "<li>(none)</li>"
    color = {"confirmed": "#0a7d2c", "refuted": "#b00020", "uncertain": "#8a6d00", "notarized": "#0a7d2c"}.get(row["verdict"], "#333")
    kind = "Automated signed check" if SERVICES.get(row["service"], {}).get("auto") else "Human-verified attestation"
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>{BRAND} attestation {att_id}</title>
    <body style="font-family:system-ui;max-width:720px;margin:48px auto;color:#1a1a1a;line-height:1.5">
      <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#666">{BRAND} · {kind}</div>
      <h1 style="margin:.2em 0">Verdict: <span style="color:{color};text-transform:capitalize">{row['verdict']}</span>
        <span style="font-size:16px;color:#666">({row['confidence']}% confidence)</span></h1>
      <p style="font-size:18px">{row['summary']}</p>
      <h3>What was checked</h3>
      <pre style="background:#f5f5f5;padding:12px;border-radius:8px;white-space:pre-wrap">{json.dumps(json.loads(row['subject']), indent=2)}</pre>
      <h3>Evidence</h3><ul>{ev_html}</ul>
      <hr style="margin:28px 0;border:none;border-top:1px solid #e5e5e5">
      <div style="font-size:13px;color:#555">
        <div><b>ID:</b> {row['id']}</div>
        <div><b>Issued:</b> {row['completed_at']} by {row['issuer']}</div>
        <div><b>Signature (ed25519):</b> <code style="word-break:break-all">{row['signature']}</code></div>
        <div><b>Public key:</b> <code style="word-break:break-all">{PUBLIC_KEY_HEX}</code></div>
        <div style="margin-top:8px">Verify independently: fetch <code>/v1/attestations/{att_id}?canonical=1</code>, then check the signature against the public key.</div>
      </div></body>""")

# ---- Human landing page ----
@app.get("/home", response_class=HTMLResponse)
def home():
    def card(v):
        auto = v.get("auto")
        badge_bg, badge_fg, badge = ("#e6f6ec", "#0a7d2c", "Instant · automated") if auto else ("#fff1e6", "#b5651d", "Human · usually ~hours")
        return f"""<div style="border:1px solid #e5e5e5;border-radius:12px;padding:20px;flex:1;min-width:240px">
        <div style="display:inline-block;margin-bottom:8px;background:{badge_bg};color:{badge_fg};font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:3px 8px;border-radius:999px">{badge}</div>
        <div style="font-weight:700;font-size:18px">{v['title']}</div>
        <div style="color:#555;margin:8px 0">{v['description']}</div>
        <div style="font-size:22px;font-weight:700;color:#2F5496">${v['price_usd']:.2f}<span style="font-size:13px;color:#888;font-weight:400"> / check</span></div>
        </div>"""
    auto_cards = "".join(card(v) for v in SERVICES.values() if v.get("auto"))
    human_cards = "".join(card(v) for v in SERVICES.values() if not v.get("auto"))
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>{BRAND}</title>
    <meta name=viewport content="width=device-width,initial-scale=1">
    <body style="font-family:system-ui;max-width:900px;margin:0 auto;padding:48px 20px;color:#1a1a1a;line-height:1.55">
      <div style="font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:#2F5496;font-weight:700">{BRAND}</div>
      <h1 style="font-size:40px;margin:.1em 0 .2em">The trust layer for AI agents.</h1>
      <p style="font-size:20px;color:#444">Agents can pay for things now — but they can't tell what's actually true.
      {BRAND} gives them signed answers: <b>instant automated checks</b> for wallets, domains, emails and content,
      plus <b>human-verified attestations</b> for the calls that need judgment. Pay per check in USDC. Every result is
      cryptographically signed — verify it yourself.</p>

      <h3 style="margin-top:34px">Instant automated checks</h3>
      <p style="color:#666;margin-top:2px">Signed result in the same response — no waiting, no human.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin:14px 0 30px">{auto_cards}</div>

      <h3>Human-verified checks</h3>
      <p style="color:#666;margin-top:2px">A real person verifies against primary sources — for the calls automation can't make.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin:14px 0 8px">{human_cards}</div>
      <div style="display:inline-block;background:#eaf1fb;color:#2F5496;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:3px 8px;border-radius:999px">Launch pricing — all services</div>

      <h3 style="margin-top:32px">How it works</h3>
      <ol><li>Your agent calls <code>POST /v1/verify</code> (or the hosted MCP server at <code>/mcp</code>) and pays via x402 (USDC).</li>
      <li>Automated checks run instantly; human checks are verified against primary sources.</li>
      <li>You get a signed verdict (confirmed / refuted / uncertain) with evidence.</li>
      <li>Anyone can verify the ed25519 signature — trust, provable.</li></ol>
      <p style="margin-top:28px"><a href="/" style="color:#2F5496">Agent manifest (JSON)</a> ·
      <a href="/mcp" style="color:#2F5496">MCP endpoint</a> ·
      <a href="mailto:{CONTACT_EMAIL}" style="color:#2F5496">Contact</a></p>
      <p style="color:#999;font-size:13px;margin-top:40px">{BRAND} returns informational, signed checks — it verifies facts and entities and does not provide legal, medical, or financial advice. Wallet screening is informational only, not compliance certification.</p>
    </body>""")

# ---- Admin console (browser) ----
@app.get("/admin", response_class=HTMLResponse)
def admin_console():
    return HTMLResponse("""<!doctype html><meta charset=utf-8><title>Attestly admin</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<body style="font-family:system-ui;max-width:900px;margin:0 auto;padding:32px 18px;color:#1a1a1a">
<h1 style="color:#2F5496">Attestly — fulfillment console</h1>
<p>Enter your admin token. <b>Load pending</b> = human jobs awaiting your verdict. <b>Load all jobs</b> = every check (incl. instant automated ones); click any row for full details.</p>
<div style="margin:12px 0">
  <input id=tok type=password placeholder="admin token" style="padding:8px;width:260px">
  <button onclick=load() style="padding:8px 14px">Load pending</button>
  <button onclick=loadAll() style="padding:8px 14px">Load all jobs</button>
  <span id=msg style="margin-left:10px;color:#666"></span>
</div>
<div id=stats style="display:flex;gap:12px;flex-wrap:wrap;margin:10px 0"></div>
<div id=legend style="display:none;font-size:12.5px;color:#555;background:#f6f8fc;border:1px solid #e2e8f5;border-radius:8px;padding:10px 12px;margin:8px 0">
  <b>Payment column:</b>
  <span style="color:#0a7d2c">verified</span> = real on-chain payment confirmed ·
  <span style="color:#8a6d00">unverified_manual</span> = accepted in manual mode, <b>no real USDC confirmed</b> (likely a test) ·
  <span style="color:#667">auto</span> = automated check (no separate payment record) ·
  <span style="color:#b00020">none</span> = no payment. Until the facilitator is wired, revenue counts every completed check — so test traffic inflates it.
</div>
<div id=list></div>
<script>
const H=()=>({'X-ADMIN-TOKEN':document.getElementById('tok').value,'content-type':'application/json'});
function tile(label,val){return `<div style="border:1px solid #e5e5e5;border-radius:10px;padding:12px 16px;min-width:110px"><div style="font-size:22px;font-weight:700;color:#2F5496">${val}</div><div style="font-size:12px;color:#666">${label}</div></div>`;}
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function payColor(p){return {verified:'#0a7d2c',unverified_manual:'#8a6d00',auto:'#667',none:'#b00020'}[p]||'#667';}
function statusChip(s){const c={completed:'#0a7d2c',pending:'#8a6d00'}[s]||'#667';return `<span style="background:${c};color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;text-transform:uppercase">${esc(s)}</span>`;}
async function loadStats(){
  const r=await fetch('/admin/stats',{headers:H()});
  if(!r.ok)return;
  const s=await r.json();
  document.getElementById('stats').innerHTML=
    tile('Total jobs',s.total_jobs)+tile('Pending',s.pending)+tile('Completed',s.completed)
    +tile('Revenue (verified)','$'+s.revenue_usd)+tile('Gross (incl. test)','$'+(s.gross_completed_usd!=null?s.gross_completed_usd:s.revenue_usd));
}
async function loadAll(){
  document.getElementById('msg').textContent='loading...';
  document.getElementById('legend').style.display='block';
  loadStats();
  const r=await fetch('/admin/jobs',{headers:H()});
  if(!r.ok){document.getElementById('msg').textContent='error '+r.status;return;}
  const jobs=await r.json();
  let real=0; jobs.forEach(j=>{if(j.status==='completed'&&j.payment_status==='verified')real+=j.price_usd;});
  document.getElementById('msg').innerHTML=jobs.length+' total · <b style="color:#0a7d2c">$'+real.toFixed(2)+' verified revenue</b>';
  const L=document.getElementById('list');L.innerHTML='';
  if(!jobs.length){L.innerHTML='<p style=color:#888>No jobs yet.</p>';return;}
  for(const j of jobs){
    const d=document.createElement('div');
    d.style.cssText='border:1px solid #e5e5e5;border-radius:10px;margin:10px 0;overflow:hidden';
    const subj=JSON.stringify(j.subject);
    const summ=subj.length>70?subj.slice(0,70)+'…':subj;
    const verdict=j.verdict?` · <b style="text-transform:capitalize">${esc(j.verdict)}</b>`:'';
    d.innerHTML=`
      <div onclick="tog('${j.id}')" style="cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center">
        ${statusChip(j.status)}
        <b>${esc(j.service)}</b>
        <span style="color:#888">$${j.price_usd.toFixed(2)}</span>
        <span style="color:${payColor(j.payment_status)};font-weight:600">${esc(j.payment_status)}</span>
        ${verdict}
        <span style="color:#aaa;font-size:12px;margin-left:auto">${esc(j.created_at)} ▾</span>
      </div>
      <div style="color:#666;font-size:12.5px;padding:0 14px 10px">${esc(summ)}</div>
      <div id="dt_${j.id}" style="display:none;border-top:1px solid #eee;padding:14px;background:#fafbfc"></div>`;
    L.appendChild(d);
    d._job=j;
  }
}
function tog(id){
  const box=document.getElementById('dt_'+id);
  if(box.style.display==='block'){box.style.display='none';return;}
  const j=[...document.getElementById('list').children].map(c=>c._job).find(x=>x&&x.id===id);
  const ev=(j.evidence||[]).map(e=>`<li>${esc(e.label||'')} ${e.url?'<a href="'+esc(e.url)+'" target=_blank>'+esc(e.url)+'</a>':''} ${esc(e.note||'')}</li>`).join('')||'<li>(none)</li>';
  box.innerHTML=`
    <div style="font-size:12px;color:#888;margin-bottom:6px">${esc(j.id)} · <a href="${esc(j.public_url)}" target=_blank>public page ↗</a> ${j.auto?'· <span style="color:#0a7d2c">automated</span>':'· human'}</div>
    <table style="font-size:13px;border-collapse:collapse">
      <tr><td style="color:#888;padding:2px 12px 2px 0">Status</td><td>${esc(j.status)}</td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Verdict</td><td>${esc(j.verdict||'—')} ${j.confidence!=null?'('+esc(j.confidence)+'%)':''}</td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Payment</td><td style="color:${payColor(j.payment_status)}">${esc(j.payment_status)}</td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Payment ref</td><td><code>${esc(j.payment_ref||'—')}</code></td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Created</td><td>${esc(j.created_at)}</td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Completed</td><td>${esc(j.completed_at||'—')}</td></tr>
      <tr><td style="color:#888;padding:2px 12px 2px 0">Issuer</td><td>${esc(j.issuer||'—')}</td></tr>
    </table>
    <div style="margin-top:8px;color:#888;font-size:12px">Summary</div><div>${esc(j.summary||'—')}</div>
    <div style="margin-top:8px;color:#888;font-size:12px">Subject</div>
    <pre style="background:#fff;border:1px solid #eee;padding:8px;border-radius:6px;white-space:pre-wrap;font-size:12px">${esc(JSON.stringify(j.subject,null,2))}</pre>
    <div style="margin-top:8px;color:#888;font-size:12px">Evidence</div><ul style="margin:4px 0">${ev}</ul>
    <div style="margin-top:8px;color:#888;font-size:12px">Signature</div><code style="word-break:break-all;font-size:11px">${esc(j.signature||'—')}</code>`;
  box.style.display='block';
}
async function load(){
  document.getElementById('msg').textContent='loading...';
  document.getElementById('legend').style.display='none';
  loadStats();
  const r=await fetch('/admin/pending',{headers:H()});
  if(!r.ok){document.getElementById('msg').textContent='error '+r.status;return;}
  const jobs=await r.json();
  document.getElementById('msg').textContent=jobs.length+' pending';
  const L=document.getElementById('list');L.innerHTML='';
  if(!jobs.length){L.innerHTML='<p style=color:#888>Nothing pending. 🎉</p>';return;}
  for(const j of jobs){
    const d=document.createElement('div');
    d.style.cssText='border:1px solid #e5e5e5;border-radius:10px;padding:16px;margin:12px 0';
    d.innerHTML=`<div style="font-size:13px;color:#888">${j.id} · ${j.service} · payment: <b>${j.payment_status}</b> · ${j.created_at}</div>
    <pre style="background:#f6f6f6;padding:10px;border-radius:8px;white-space:pre-wrap">${JSON.stringify(j.subject,null,2)}</pre>
    <label>Verdict
      <select id="v_${j.id}"><option value=confirmed>confirmed</option><option value=refuted>refuted</option><option value=uncertain>uncertain</option></select>
    </label>
    &nbsp;Confidence <input id="c_${j.id}" type=number min=0 max=100 value=90 style="width:64px">
    <br><input id="s_${j.id}" placeholder="one-line summary" style="width:100%;padding:6px;margin:8px 0">
    <input id="el_${j.id}" placeholder="evidence label (e.g. AZ Corp Commission)" style="width:48%;padding:6px">
    <input id="eu_${j.id}" placeholder="evidence url" style="width:48%;padding:6px">
    <br><button style="margin-top:10px;padding:8px 14px;background:#2F5496;color:#fff;border:0;border-radius:6px" onclick="done('${j.id}')">Sign & publish</button>
    <span id="r_${j.id}" style="margin-left:10px"></span>`;
    L.appendChild(d);
  }
}
async function done(id){
  const ev=[]; const el=document.getElementById('el_'+id).value, eu=document.getElementById('eu_'+id).value;
  if(el||eu) ev.push({label:el,url:eu});
  const body={verdict:document.getElementById('v_'+id).value,
    summary:document.getElementById('s_'+id).value,
    confidence:parseInt(document.getElementById('c_'+id).value||'90'),evidence:ev};
  const r=await fetch('/admin/attestations/'+id+'/complete',{method:'POST',headers:H(),body:JSON.stringify(body)});
  const out=document.getElementById('r_'+id);
  if(r.ok){const j=await r.json();out.innerHTML='✅ <a href="'+j.public_url+'" target=_blank>published</a>';}
  else out.textContent='error '+r.status;
}
</script></body>""")
