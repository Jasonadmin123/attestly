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
import asyncio
import hashlib
import sqlite3
import secrets
import time as _time
from datetime import datetime, timezone, timedelta
from contextlib import closing, asynccontextmanager
from collections import defaultdict, deque

import httpx
import whois
import dns.resolver
from fastmcp import FastMCP
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from nacl.signing import SigningKey, VerifyKey
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
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "").rstrip("/")   # override; else derived from network
ALLOW_UNVERIFIED = os.environ.get("ALLOW_UNVERIFIED_PAYMENTS", "true").lower() == "true"
CONTACT_EMAIL  = os.environ.get("CONTACT_EMAIL", "you@yourdomain.com")
# Pricing policy (machine-readable, surfaced to agent customers).
PRICING_VERSION = os.environ.get("PRICING_VERSION", "2026.07")
PRICING_STATUS  = os.environ.get("PRICING_STATUS", "introductory")
PRICE_CHANGE_NOTICE_DAYS = int(os.environ.get("PRICE_CHANGE_NOTICE_DAYS", "14"))
PRICING_EFFECTIVE_DATE   = os.environ.get("PRICING_EFFECTIVE_DATE") or None  # set when a change is scheduled
# Moltbook activity alerts (interim, until the engagement bot exists). Emails you when
# a new comment/reply lands on your posts so you know to respond. Dormant unless the key is set.
MOLTBOOK_API_KEY = os.environ.get("MOLTBOOK_API_KEY")
MOLTBOOK_POLL_MINUTES = int(os.environ.get("MOLTBOOK_POLL_MINUTES", "15"))
MOLTBOOK_STATE_PATH = os.environ.get("MOLTBOOK_STATE",
                                     os.path.join(os.path.dirname(DB_PATH) or ".", "moltbook_state.json"))

# --- x402 facilitator (real payments) -------------------------------------
# CAIP-2 network. Default Base mainnet; set eip155:84532 for Base Sepolia testnet dry-runs.
# The facilitator stays DORMANT (manual mode) on mainnet until CDP keys are present, so
# deploying this changes nothing until you deliberately add CDP_API_KEY_ID/SECRET.
PAY_NETWORK_CAIP = os.environ.get("PAY_NETWORK_CAIP", "eip155:8453")
CDP_API_KEY_ID     = os.environ.get("CDP_API_KEY_ID")
CDP_API_KEY_SECRET = os.environ.get("CDP_API_KEY_SECRET")
# Everything below is optional & defensive: if x402 libs or config are absent,
# the service falls back to manual mode exactly as before (never crashes on import).
_X402_OK = False
_X402_ASSET = None
try:
    from x402.mechanisms.evm.constants import NETWORK_CONFIGS as _NETCFG
    from x402.http import (HTTPFacilitatorClientSync as _FacClient,
                           FacilitatorConfig as _FacConfig,
                           CreateHeadersAuthProvider as _AuthProvider,
                           safe_base64_decode as _b64d)
    from x402.schemas.payments import PaymentRequirements as _PayReq
    from x402.schemas.helpers import parse_payment_payload as _parse_payload
    _cfg = _NETCFG.get(PAY_NETWORK_CAIP)
    if _cfg:
        _X402_ASSET = _cfg["default_asset"]   # {address,name,version,decimals}
        _X402_OK = True
except Exception:
    _X402_OK = False

# Facilitator URL: explicit override, else CDP for mainnet, else public testnet facilitator.
if FACILITATOR_URL:
    _FAC_URL = FACILITATOR_URL
elif PAY_NETWORK_CAIP == "eip155:8453":
    _FAC_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
else:
    _FAC_URL = "https://x402.org/facilitator"

_FACILITATOR_SINGLETON = None
def _cdp_auth_provider():
    """CDP JWT auth for the mainnet facilitator; None for the keyless testnet facilitator."""
    if not (CDP_API_KEY_ID and CDP_API_KEY_SECRET and "cdp.coinbase.com" in _FAC_URL):
        return None
    from cdp.auth.utils.http import get_auth_headers, GetAuthHeadersOptions
    from urllib.parse import urlparse
    u = urlparse(_FAC_URL); host = u.netloc; base = u.path.rstrip("/")
    def _headers():
        def hdr(op, method):
            return get_auth_headers(GetAuthHeadersOptions(
                api_key_id=CDP_API_KEY_ID, api_key_secret=CDP_API_KEY_SECRET,
                request_method=method, request_host=host, request_path=f"{base}/{op}"))
        # Methods must match the client's actual requests: verify/settle POST, supported GET.
        return {"verify": hdr("verify", "POST"), "settle": hdr("settle", "POST"),
                "supported": hdr("supported", "GET"), "bazaar": {}}
    return _AuthProvider(_headers)

def _facilitator():
    global _FACILITATOR_SINGLETON
    if _FACILITATOR_SINGLETON is None:
        _FACILITATOR_SINGLETON = _FacClient(_FacConfig(url=_FAC_URL, auth_provider=_cdp_auth_provider()))
    return _FACILITATOR_SINGLETON

def _payment_requirements(service_key: str):
    """Spec-compliant x402 PaymentRequirements for a service (correct asset + EIP-712 domain)."""
    svc = SERVICES[service_key]
    atomic = str(int(round(svc["price_usd"] * (10 ** _X402_ASSET["decimals"]))))
    return _PayReq(scheme="exact", network=PAY_NETWORK_CAIP, asset=_X402_ASSET["address"],
                   amount=atomic, pay_to=PAYTO_ADDRESS, max_timeout_seconds=300,
                   extra={"name": _X402_ASSET["name"], "version": _X402_ASSET["version"]})

def facilitator_active() -> bool:
    """True when we can actually verify+settle real payments (libs ok + mainnet CDP keys, or testnet)."""
    if not _X402_OK:
        return False
    if PAY_NETWORK_CAIP == "eip155:8453":
        return bool(CDP_API_KEY_ID and CDP_API_KEY_SECRET)
    return True   # testnet facilitator is keyless
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
        "description": "Submit content or a SHA-256 hash; get an instant ed25519-signed proof it existed at this time. Free — try Attestly with no payment.",
        "price_usd": 0.00, "auto": True, "free": True,
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
    "agent_verify": {
        "title": "Agent identity verification",
        "description": "Instantly verify another agent is who it claims: fetches and validates its A2A agent card, confirms domain control (DNS/TLS/host match), and optionally verifies ed25519 key control via a signed message. Know your counterparty agent before you trust or transact.",
        "price_usd": 0.75, "auto": True,
    },
}

# --- Free-tier flip (bureau strategy: give the automated checks away to accumulate the
#     data asset — every check becomes a row in an agent's file). Flip back by setting
#     ALL_AUTO_FREE=false to restore the paid prices above. Human checks always stay paid.
ALL_AUTO_FREE = os.environ.get("ALL_AUTO_FREE", "true").lower() == "true"
if ALL_AUTO_FREE:
    for _k, _v in SERVICES.items():
        if _v.get("auto"):
            _v["price_usd"] = 0.00
            _v["free"] = True

# --- Cost / abuse guardrails (so "free" can never turn into "expensive" or "abused").
#     All in-memory + env-tunable; no external cost. Enforced centrally in run_auto().
AUTO_CHECKS_ENABLED = os.environ.get("AUTO_CHECKS_ENABLED", "true").lower() == "true"  # master kill-switch
FREE_DAILY_CEILING  = int(os.environ.get("FREE_DAILY_CEILING", "3000"))   # max automated checks/day, platform-wide
RATE_PER_MIN        = int(os.environ.get("RATE_PER_MIN", "30"))           # per-IP requests/min on /v1/verify
CACHE_TTL_MIN       = int(os.environ.get("CACHE_TTL_MIN", "60"))          # dedupe identical (service,subject) lookups
SPIKE_ALERT_AT      = int(os.environ.get("SPIKE_ALERT_AT", "1000"))       # email once/day when daily count crosses this
_AUTO_CACHE: dict = {}                    # (service, subject_key) -> (result_dict, epoch_ts)
_DAILY = {"day": None, "count": 0, "alerted": False}
_RATE_HITS: dict = defaultdict(deque)     # ip -> deque[epoch_ts]

class GuardrailBlock(Exception):
    """Raised to short-circuit an automated check without an error stack (kill-switch / daily ceiling)."""
    def __init__(self, code: str, message: str, status: int = 429):
        self.code = code; self.message = message; self.status = status
        super().__init__(message)

def pricing_notice(service_key: str | None = None) -> str:
    if service_key and SERVICES.get(service_key, {}).get("price_usd", 0) <= 0:
        return (f"This service is FREE during Attestly's introductory period (v{PRICING_VERSION}). "
                f"Paid services will rise as the service matures; ≥{PRICE_CHANGE_NOTICE_DAYS}d notice before any change. See {BASE_URL}/pricing.")
    return (f"Introductory pricing (v{PRICING_VERSION}) — intentionally low to build a track record; prices will rise "
            f"as the service matures. The price quoted at request time is locked for that request, with ≥{PRICE_CHANGE_NOTICE_DAYS} "
            f"days' machine-readable notice before any change (poll {BASE_URL}/pricing; watch pricing.version).")

def pricing_policy() -> dict:
    """Machine-readable pricing terms for agent customers. Honest + actionable:
    introductory pricing now, will rise as the service matures, with guarantees an agent can rely on."""
    return {
        "version": PRICING_VERSION,
        "status": PRICING_STATUS,   # "introductory" -> "standard" later
        "currency": PAY_ASSET,
        "network": PAY_NETWORK_CAIP,
        "notice": ("Introductory pricing: intentionally low while Attestly builds a track record with "
                   "early agents. Prices will increase as the service matures. Any change is published here "
                   f"with an effective_date at least {PRICE_CHANGE_NOTICE_DAYS} days before it applies — "
                   "compare pricing.version to detect changes. Integrating now locks in today's rates under "
                   "the guarantees below."),
        "free_services": [k for k, v in SERVICES.items() if v.get("price_usd", 0) <= 0],
        "services": {k: {"price_usd": v["price_usd"], "free": v.get("price_usd", 0) <= 0,
                         "type": "automated" if v.get("auto") else "human"}
                     for k, v in SERVICES.items()},
        "guarantees": {
            "price_lock": "The price quoted in the 402 challenge at request time is honored for that request; changes never apply retroactively.",
            "advance_notice_days": PRICE_CHANGE_NOTICE_DAYS,
            "detect_changes": "pricing.version bumps on any change; poll GET /pricing.",
        },
        "effective_date": PRICING_EFFECTIVE_DATE,   # non-null only when a change is scheduled
        "terms_url": f"{BASE_URL}/pricing",
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
        # The "memory": one row per completed check, indexed by the subject being checked
        # (wallet / agent / domain / email). This is the bureau file that compounds over time —
        # the whole point of running the checks free. Stamps sell for pennies; files don't.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_key TEXT NOT NULL, subject_type TEXT NOT NULL,
                service TEXT NOT NULL, verdict TEXT, confidence INTEGER, summary TEXT,
                facts TEXT, attestation_id TEXT, payment_status TEXT, created_at TEXT NOT NULL
            )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_records_key ON agent_records(subject_key)")
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
# x402 Bazaar (Coinbase CDP discovery layer) — declared on PAID endpoints so the
# facilitator indexes them the first time a payment settles. Per-service input/output.
_BAZAAR_EXAMPLES = {
    "entity_check": {
        "input": {"service": "entity_check", "subject": {"business": "Acme Lending LLC", "state": "AZ"}},
        "subject_props": {"business": {"type": "string"}, "state": {"type": "string"}},
        "subject_required": ["business"],
        "output": {"status": "completed", "verdict": "confirmed", "confidence": 0.92,
                   "attestation_id": "at_1a2b3c4d5e6f7080",
                   "data": {"name": "Acme Lending LLC", "status": "active", "jurisdiction": "AZ"},
                   "signature": "<ed25519 hex signature>", "public_key": "<ed25519 hex public key>"},
    },
    "claim_check": {
        "input": {"service": "claim_check",
                  "subject": {"claim": "example.com is the official site of Example Corp",
                              "url": "https://example.com"}},
        "subject_props": {"claim": {"type": "string"}, "url": {"type": "string"}},
        "subject_required": ["claim"],
        "output": {"status": "completed", "verdict": "confirmed", "confidence": 0.88,
                   "attestation_id": "at_9f8e7d6c5b4a3021",
                   "data": {"claim": "example.com is the official site of Example Corp",
                            "sources": ["https://example.com/about"]},
                   "signature": "<ed25519 hex signature>", "public_key": "<ed25519 hex public key>"},
    },
}

def _bazaar_extension(service_key):
    """Return (v2_extension, v1_output_schema) for a paid, discoverable endpoint, else (None, None)."""
    spec = _BAZAAR_EXAMPLES.get(service_key)
    if not spec:
        return None, None
    svc = SERVICES[service_key]
    input_schema = {
        "type": "object",
        "properties": {
            "service": {"type": "string", "enum": [service_key]},
            "subject": {"type": "object", "properties": spec["subject_props"],
                        "required": spec["subject_required"]},
        },
        "required": ["service", "subject"],
    }
    ext = {
        "info": {"method": "POST", "input": spec["input"], "bodyType": "json",
                 "output": {"example": spec["output"]}},
        "schema": input_schema,
        "description": svc["description"],
    }
    output_schema = {
        "type": "object", "description": svc["description"],
        "properties": {
            "status": {"type": "string"},
            "verdict": {"type": "string", "enum": ["confirmed", "refuted", "uncertain"]},
            "confidence": {"type": "number"}, "attestation_id": {"type": "string"},
            "data": {"type": "object"}, "signature": {"type": "string"}, "public_key": {"type": "string"},
        },
        "example": spec["output"],
    }
    return ext, output_schema

def x402_challenge(service_key: str) -> JSONResponse:
    svc = SERVICES[service_key]
    accepts = []
    # Spec-compliant x402 requirements (correct USDC address + EIP-712 domain per network).
    if _X402_OK:
        try:
            req = _payment_requirements(service_key).model_dump(by_alias=True)
            req["resource"] = f"{BASE_URL}/v1/verify"
            req["description"] = svc["title"]
            req["mimeType"] = "application/json"
            accepts.append(req)
        except Exception:
            pass
    if not accepts:   # fallback human-readable form
        accepts.append({"scheme": "exact", "network": PAY_NETWORK, "asset": PAY_ASSET,
                        "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS,
                        "resource": f"{BASE_URL}/v1/verify", "description": svc["title"],
                        "mimeType": "application/json"})
    content = {
        "x402Version": 2 if _X402_OK else 1, "error": "payment_required",
        "accepts": accepts,
        "note": "Pay the amount above in USDC, then retry with header 'X-PAYMENT: <payload>'.",
        "pricing_notice": pricing_notice(service_key),
        "pricing_url": f"{BASE_URL}/pricing",
    }
    # Attach x402 Bazaar discovery declaration on paid endpoints (indexed on first settle).
    try:
        _ext, _out = _bazaar_extension(service_key)
        if _ext:
            content["extensions"] = {"bazaar": _ext}
            for _req in accepts:
                if isinstance(_req, dict):
                    _req.setdefault("outputSchema", _out)
    except Exception:
        pass
    return JSONResponse(status_code=402, content=content)

def check_payment(proof: str | None, service_key: str) -> tuple[bool, str, str | None]:
    """
    Returns (accepted, payment_status, tx_ref).
    Order of preference:
      1. Real x402 facilitator: parse the X-PAYMENT payload, VERIFY it, then SETTLE it
         on-chain. Only 'verified' (with a tx hash) means money actually moved.
      2. If the proof isn't a real x402 payload (or the facilitator errors) and manual
         mode is on, accept it flagged 'unverified_manual' so YOU reconcile by hand.
      3. Otherwise reject.
    """
    # Free services (price 0) never require payment — the cheap on-ramp.
    if SERVICES.get(service_key, {}).get("price_usd", 0) <= 0:
        return (True, "free", None)
    if not proof:
        return (False, "none", None)
    # Try the real facilitator path first.
    if facilitator_active():
        try:
            payload = _parse_payload(_b64d(proof))          # base64 X-PAYMENT -> PaymentPayload
        except Exception:
            payload = None
        if payload is not None:
            try:
                reqs = _payment_requirements(service_key)
                v = _facilitator().verify(payload, reqs)
                if not getattr(v, "is_valid", False):
                    notify_payment_problem(service_key, "verify_rejected")
                    return (False, "rejected", None)
                s = _facilitator().settle(payload, reqs)
                if getattr(s, "success", False):
                    return (True, "verified", getattr(s, "transaction", None))
                notify_payment_problem(service_key, "settle_failed")
                return (False, "settle_failed", None)
            except Exception:
                notify_payment_problem(service_key, "facilitator_error")
                if ALLOW_UNVERIFIED:
                    return (True, "unverified_manual", None)
                return (False, "facilitator_error", None)
    # Manual fallback (launch mode): accept a non-empty proof, flag for hand reconciliation.
    if ALLOW_UNVERIFIED:
        return (True, "unverified_manual", None)
    return (False, "no_facilitator", None)

# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------
def _send_email(subject: str, text: str) -> None:
    """Fire-and-forget email alert via Resend. Never breaks the request if email fails."""
    if not RESEND_API_KEY:
        return
    try:
        httpx.post("https://api.resend.com/emails",
                   headers={"Authorization": "Bearer " + RESEND_API_KEY, "Content-Type": "application/json"},
                   json={"from": ALERT_FROM, "to": [ALERT_EMAIL], "subject": subject, "text": text},
                   timeout=8)
    except Exception:
        pass

def notify_new_job(att_id: str, service: str) -> None:
    _send_email(f"Attestly 💰 new {service} job",
                f"You have a new {service} request.\n\nJob id: {att_id}\n\n"
                f"Next step: open {BASE_URL}/admin, verify it against sources, then Sign & publish.\n"
                f"(Confirm the USDC landed in your wallet first.)")

def notify_paid(att_id: str, service: str, tx_ref: str | None) -> None:
    """A real x402 payment settled on-chain. This is real money."""
    price = SERVICES.get(service, {}).get("price_usd", 0)
    _send_email(f"Attestly 💰💰 REAL PAYMENT — {service} (${price:.2f})",
                f"A real payment just settled on-chain.\n\nService: {service}\nAmount: ${price:.2f} USDC\n"
                f"Job id: {att_id}\nTx: {tx_ref or '(see wallet)'}\n\n"
                f"Check your Base wallet and {BASE_URL}/admin (Load all jobs).")

def notify_payment_problem(service: str, status: str) -> None:
    """A real x402 payment was attempted but did not settle cleanly — investigate."""
    _send_email(f"Attestly ⚠️ payment attempt did NOT settle — {service} ({status})",
                f"An agent attempted to pay for '{service}' but it did not settle cleanly (status: {status}).\n\n"
                f"This may mean a payment-format/version mismatch. The check was NOT served for real money.\n"
                f"Investigate {BASE_URL}/admin/facilitator and the facilitator logs. First real payment = expected test point.")

# ----------------------------------------------------------------------------
# Moltbook activity alerts (interim). Polls your Moltbook dashboard and emails
# you when a new comment/reply lands on your posts, so you know when to respond.
# ----------------------------------------------------------------------------
def _moltbook_load_state() -> dict:
    try:
        with open(MOLTBOOK_STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def _moltbook_save_state(state: dict) -> None:
    try:
        with open(MOLTBOOK_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def moltbook_check() -> None:
    """One poll: fetch /home, email about posts with new activity since last seen."""
    if not MOLTBOOK_API_KEY:
        return
    try:
        h = httpx.get("https://www.moltbook.com/api/v1/home",
                      headers={"Authorization": "Bearer " + MOLTBOOK_API_KEY}, timeout=15).json()
    except Exception:
        return
    acts = h.get("activity_on_your_posts") or []
    state = _moltbook_load_state()
    seen = state.get("posts", {})
    fresh = []
    for a in acts:
        pid = a.get("post_id")
        latest = str(a.get("latest_at"))
        if pid and seen.get(pid) != latest:
            fresh.append(a)
    if fresh:
        lines = []
        for a in fresh:
            who = ", ".join(a.get("latest_commenters") or []) or "someone"
            lines.append(f'- "{a.get("post_title")}": {a.get("new_notification_count")} new from {who}')
        _send_email("Attestly · Moltbook 💬 new activity — time to respond",
                    "New comments/replies on your Moltbook posts:\n\n" + "\n".join(lines) +
                    "\n\nRespond here: https://www.moltbook.com/u/attestly\n"
                    f"(Unread notifications: {h.get('your_account', {}).get('unread_notification_count')})")
        for a in fresh:
            seen[a.get("post_id")] = str(a.get("latest_at"))
        state["posts"] = seen
        _moltbook_save_state(state)

async def _moltbook_poll_loop() -> None:
    # small initial delay so startup isn't blocked
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.to_thread(moltbook_check)
        except Exception:
            pass
        await asyncio.sleep(max(5, MOLTBOOK_POLL_MINUTES) * 60)

# ----------------------------------------------------------------------------
# Traffic metrics — count discovery + intent hits so you can see interest
# before revenue. In-memory deltas, flushed to SQLite periodically.
# ----------------------------------------------------------------------------
_METRIC_DELTAS: dict = defaultdict(int)

def _metric_label(path: str, status: int) -> str | None:
    """Map a request to a meaningful metric label, or None to ignore (health/admin/noise)."""
    p = path.rstrip("/") or "/"
    if p == "/": return "manifest"
    if p.startswith("/.well-known/agent"): return "agent_card"
    if p == "/.well-known/attestly-pubkey": return "pubkey"
    if p == "/llms.txt": return "llms_txt"
    if p.startswith("/pricing"): return "pricing"
    if p == "/home": return "home"
    if p == "/mcp" or p.startswith("/mcp/"): return "mcp"
    if p == "/v1/verify":
        if status == 402: return "verify_payment_prompt"   # agent hit the paywall = intent
        if status == 200: return "verify_completed"
        return "verify_other"
    if p.startswith("/a/"): return "attestation_view"       # public signed-result page
    if p.startswith("/v1/attestations"): return "attestation_api"
    if p.startswith("/v1/profile"): return "profile_pull"    # someone queried an agent's file = bureau intent
    return None

def _record_metric(path: str, status: int) -> None:
    lbl = _metric_label(path, status)
    if not lbl:
        return
    day = now_iso()[:10]
    _METRIC_DELTAS[(day, lbl)] += 1

def _flush_metrics() -> None:
    if not _METRIC_DELTAS:
        return
    deltas = dict(_METRIC_DELTAS); _METRIC_DELTAS.clear()
    try:
        with closing(db()) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS metrics (day TEXT, label TEXT, count INTEGER, PRIMARY KEY(day,label))")
            for (day, lbl), c in deltas.items():
                conn.execute("INSERT INTO metrics (day,label,count) VALUES (?,?,?) "
                             "ON CONFLICT(day,label) DO UPDATE SET count=count+excluded.count", (day, lbl, c))
            conn.commit()
    except Exception:
        # on failure, put deltas back so we don't lose them
        for k, v in deltas.items():
            _METRIC_DELTAS[k] += v

async def _metrics_flush_loop() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            await asyncio.to_thread(_flush_metrics)
        except Exception:
            pass

# ----------------------------------------------------------------------------
# Automated checks (no human) — run synchronously, sign, return completed.
# ----------------------------------------------------------------------------
# --- The memory: derive the subject identity a check is ABOUT, and file the row. -------------
def _subject_key(service: str, subject: dict):
    """The identity a check is about → (key, type). This is what the bureau file is indexed on."""
    s = subject or {}
    if service == "wallet_screen":
        a = (s.get("address") or "").strip().lower();  return (a, "wallet") if a else (None, None)
    if service == "agent_verify":
        a = (s.get("agent") or "").strip().lower()
        if a.startswith("http"):
            try:
                from urllib.parse import urlparse
                a = urlparse(a).netloc.lower() or a
            except Exception:
                pass
        return (a, "agent") if a else (None, None)
    if service == "domain_check":
        d = (s.get("domain") or "").strip().lower();   return (d, "domain") if d else (None, None)
    if service == "email_check":
        e = (s.get("email") or "").strip().lower();    return (e, "email") if e else (None, None)
    if service == "notarize":
        h = (s.get("sha256") or "").strip().lower();   return (h, "content") if h else (None, None)
    return (None, None)

def _record_agent(service, subject, verdict, confidence, summary, data, att_id, payment_status):
    """Write one bureau row for the subject checked. Fails safe — never breaks a check."""
    key, ktype = _subject_key(service, subject)
    if not key:
        return
    try:
        facts = json.dumps(data or {}, separators=(",", ":"))[:2000]
        with closing(db()) as conn:
            conn.execute(
                "INSERT INTO agent_records (subject_key,subject_type,service,verdict,confidence,summary,facts,attestation_id,payment_status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, ktype, service, verdict, confidence, summary, facts, att_id, payment_status or "auto", now_iso()))
            conn.commit()
    except Exception:
        pass

# --- Guardrails: kill-switch, daily ceiling, per-IP rate limit, dedupe cache. In-memory, free. --
def _ceiling_check_and_incr():
    d = now_iso()[:10]
    if _DAILY["day"] != d:
        _DAILY["day"] = d; _DAILY["count"] = 0; _DAILY["alerted"] = False
    if _DAILY["count"] >= FREE_DAILY_CEILING:
        raise GuardrailBlock("free_capacity_reached",
                             f"Free daily capacity ({FREE_DAILY_CEILING}) reached — retry tomorrow.", status=429)
    _DAILY["count"] += 1
    if (not _DAILY["alerted"]) and _DAILY["count"] >= SPIKE_ALERT_AT:
        _DAILY["alerted"] = True
        _send_email("Attestly ⚡ traffic spike",
                    f"Automated checks today crossed {SPIKE_ALERT_AT} ({_DAILY['count']} so far; ceiling {FREE_DAILY_CEILING}). "
                    f"No cost impact (no paid APIs), just a heads-up. Kill-switch: set AUTO_CHECKS_ENABLED=false to pause.")

def _rate_ok(ip: str) -> bool:
    if RATE_PER_MIN <= 0:
        return True
    now = _time.time(); dq = _RATE_HITS[ip]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= RATE_PER_MIN:
        return False
    dq.append(now); return True

def _cache_key(service: str, subject: dict) -> str:
    """Dedupe on the FULL request (identity + all params), not just identity — a key-proof
    agent_verify is a different question than a bare one, so they must not share a cache entry."""
    try:
        blob = json.dumps(subject or {}, sort_keys=True, separators=(",", ":"))
    except Exception:
        blob = str(subject)
    return service + ":" + hashlib.sha256(blob.encode()).hexdigest()[:32]

def _cache_get(key):
    if CACHE_TTL_MIN <= 0 or not key:
        return None
    hit = _AUTO_CACHE.get(key)
    if not hit:
        return None
    result, ts = hit
    if _time.time() - ts > CACHE_TTL_MIN * 60:
        _AUTO_CACHE.pop(key, None); return None
    out = dict(result); out["cached"] = True; return out

def _cache_put(key, result):
    if CACHE_TTL_MIN > 0 and key:
        _AUTO_CACHE[key] = (result, _time.time())

def finalize_auto(service: str, subject: dict, verdict: str, confidence: int,
                  summary: str, evidence=None, data=None,
                  payment_status: str = "auto", payment_ref: str | None = None) -> dict:
    """Create an already-completed, signed attestation for an automated check.
    payment_status: 'verified' (real settled payment) counts as revenue; 'auto' = free/test."""
    evidence = evidence or []
    att_id = "at_" + secrets.token_hex(8)
    now = now_iso()
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO attestations (id,service,subject,status,verdict,summary,evidence,confidence,payment_ref,payment_status,created_at,completed_at,issuer) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (att_id, service, json.dumps(subject), "completed", verdict, summary,
             json.dumps(evidence), confidence, payment_ref, payment_status or "auto", now, now, "Attestly automated check"))
        conn.commit()
        row = conn.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
        sig = SIGNING_KEY.sign(canonical_payload(row).encode(), encoder=HexEncoder).signature.decode()
        conn.execute("UPDATE attestations SET signature=? WHERE id=?", (sig, att_id))
        conn.commit()
    # File the row in the subject's bureau record (the compounding data asset).
    _record_agent(service, subject, verdict, confidence, summary, data, att_id, payment_status)
    if payment_status == "verified":
        notify_paid(att_id, service, payment_ref)   # real money settled
    return {"attestation_id": att_id, "status": "completed", "verdict": verdict,
            "confidence": confidence, "summary": summary, "evidence": evidence,
            "data": data or {}, "signature": sig, "public_key": PUBLIC_KEY_HEX,
            "public_url": f"{BASE_URL}/a/{att_id}",
            "pricing_notice": pricing_notice(service)}

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

def run_agent_verify(subject: dict):
    """Verify another agent's identity: valid A2A agent card + domain control + optional key control."""
    agent = (subject.get("agent") or "").strip()
    if not agent:
        raise ValueError("provide 'agent' — a domain (example.com) or a full agent-card URL")
    expected_name = (subject.get("expected_name") or "").strip()
    pub = (subject.get("public_key") or "").strip()
    msg = subject.get("message")
    sig = (subject.get("signature") or "").strip()

    # Candidate agent-card URLs.
    candidates = []
    if agent.startswith("http"):
        candidates.append(agent)
        m = re.match(r"(https?://[^/]+)", agent)
        if m:
            candidates += [m.group(1) + "/.well-known/agent.json", m.group(1) + "/.well-known/agent-card.json"]
        host = re.sub(r"^https?://", "", agent).split("/")[0]
    else:
        host = re.sub(r"^https?://", "", agent).split("/")[0].split(":")[0]
        candidates += [f"https://{host}/.well-known/agent.json", f"https://{host}/.well-known/agent-card.json"]

    card = card_url = None
    for u in candidates:
        try:
            r = httpx.get(u, timeout=8, follow_redirects=True)
            if r.status_code == 200:
                j = r.json()
                if isinstance(j, dict) and (j.get("name") or j.get("skills") or j.get("protocolVersion")):
                    card, card_url = j, u
                    break
        except Exception:
            continue

    card_found = card is not None
    card_name = (card or {}).get("name")
    protocol_version = (card or {}).get("protocolVersion")
    card_url_field = (card or {}).get("url") or ((card or {}).get("provider") or {}).get("url")
    url_host = re.sub(r"^https?://", "", card_url_field).split("/")[0].split(":")[0] if card_url_field else None

    # Domain resolves + TLS valid (reuse the same signals as domain_check).
    resolves = ssl_valid = False
    check_host = url_host or host
    try:
        dns.resolver.resolve(check_host, "A", lifetime=5); resolves = True
    except Exception: pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((check_host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=check_host) as ss:
                ss.getpeercert(); ssl_valid = True
    except Exception: pass

    host_match = (url_host is None) or (url_host == host) or (host in (url_host or "")) or ((url_host or "") in host)
    name_match = (not expected_name) or (expected_name.lower() == (card_name or "").lower())

    # Optional cryptographic key control.
    key_verified = None
    if pub and sig and msg is not None:
        try:
            VerifyKey(pub, encoder=HexEncoder).verify(str(msg).encode(), bytes.fromhex(sig))
            key_verified = True
        except Exception:
            key_verified = False

    flags = []
    if not card_found: flags.append("no valid agent card found")
    if not resolves: flags.append("domain does not resolve")
    if not ssl_valid: flags.append("no/invalid TLS")
    if not host_match: flags.append("card url host != queried domain")
    if not name_match: flags.append("name mismatch")
    if key_verified is False: flags.append("signature invalid")
    if key_verified is True: flags.append("key control proven")

    if not card_found or not resolves or not host_match or not name_match or key_verified is False:
        verdict, conf = "refuted", 90
    elif ssl_valid and (key_verified is True or key_verified is None):
        verdict, conf = ("confirmed", 92 if key_verified else 80)
        if key_verified is None:
            flags.append("identity consistent; key control not proven (no signature provided)")
    else:
        verdict, conf = "uncertain", 60

    summary = (f"{check_host}: card={'found' if card_found else 'missing'}"
               + (f" ('{card_name}')" if card_name else "")
               + f", resolves={resolves}, TLS={'valid' if ssl_valid else 'no'}, host_match={host_match}"
               + (f", key_verified={key_verified}" if key_verified is not None else "")
               + f" → {verdict}.")
    data = {"agent": agent, "card_url": card_url, "card_found": card_found, "card_name": card_name,
            "protocol_version": protocol_version, "card_url_host": url_host, "resolves": resolves,
            "tls_valid": ssl_valid, "host_match": host_match, "name_match": name_match,
            "key_verified": key_verified, "flags": flags}
    evidence = [{"label": "agent_card", "note": f"found={card_found} at {card_url}"},
                {"label": "domain", "note": f"host={check_host}, resolves={resolves}, tls={ssl_valid}"},
                {"label": "key_control", "note": f"verified={key_verified}"}]
    return (verdict, conf, summary, evidence, data, {"agent": agent, "expected_name": expected_name or None})

AUTO_RUNNERS = {
    "notarize": run_notarize,
    "domain_check": run_domain_check,
    "email_check": run_email_check,
    "wallet_screen": run_wallet_screen,
    "agent_verify": run_agent_verify,
}

def run_auto(service: str, subject: dict, payment_status: str = "auto", payment_ref: str | None = None) -> dict:
    """Run an automated check and return a signed, completed attestation.
    Guardrails (kill-switch → dedupe cache → daily ceiling) are enforced here so BOTH the
    HTTP and MCP paths are protected. Cache hits and disabled/ceiling blocks do no external work."""
    if not AUTO_CHECKS_ENABLED:
        raise GuardrailBlock("auto_disabled", "Automated checks are temporarily paused. Try again later.", status=503)
    ckey = _cache_key(service, subject)
    if service != "notarize":                      # notarize is pure local hashing — no need to cache
        cached = _cache_get(ckey)
        if cached is not None:
            return cached
    _ceiling_check_and_incr()
    verdict, conf, summary, evidence, data, stored_subject = AUTO_RUNNERS[service](subject)
    result = finalize_auto(service, stored_subject, verdict, conf, summary, evidence, data,
                           payment_status=payment_status, payment_ref=payment_ref)
    if service != "notarize":
        _cache_put(ckey, result)
    return result

# ----------------------------------------------------------------------------
# Hosted MCP server (remote, callable at /mcp) — so any MCP agent can use Attestly
# by URL, no install. Tools reuse the internal logic below.
# ----------------------------------------------------------------------------
_mcp = FastMCP("Attestly")

@_mcp.tool
def get_services() -> dict:
    """List Attestly's verification services, prices (USDC), and how payment works."""
    return {"services": SERVICES,
            "payment": {"protocol": "x402", "network": PAY_NETWORK_CAIP, "asset": PAY_ASSET, "pay_to": PAYTO_ADDRESS}}

@_mcp.tool
def request_verification(service: str, subject: dict, payment: str = "") -> dict:
    """Ask a real human to verify a fact or an entity, returned as a signed attestation.
    service: 'entity_check' (does this business/entity exist & match?) or 'claim_check' (is this claim/URL true?).
    subject: what to verify, e.g. {"business":"Acme LLC","state":"AZ","claim":"is registered"}.
    payment: your x402 payment proof. Omit to first receive payment requirements, then pay and call again."""
    if service not in SERVICES:
        return {"error": f"unknown service '{service}'. Use get_services()."}
    accepted, pay_status, tx_ref = check_payment(payment or None, service)
    if not accepted:
        svc = SERVICES[service]
        return {"payment_required": {"protocol": "x402", "network": PAY_NETWORK_CAIP, "asset": PAY_ASSET,
                                     "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS},
                "note": "Pay the amount in USDC, then call request_verification again with the payment proof."}
    att_id = "at_" + secrets.token_hex(8)
    with closing(db()) as conn:
        conn.execute("INSERT INTO attestations (id,service,subject,status,payment_ref,payment_status,created_at) VALUES (?,?,?,?,?,?,?)",
                     (att_id, service, json.dumps(subject), "pending", (tx_ref or (payment or "")[:80]), pay_status, now_iso()))
        conn.commit()
    notify_new_job(att_id, service)
    if pay_status == "verified":
        notify_paid(att_id, service, tx_ref)
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
    accepted, _, _ = check_payment(payment or None, service)
    if not accepted:
        svc = SERVICES[service]
        return {"payment_required": {"protocol": "x402", "network": PAY_NETWORK_CAIP, "asset": PAY_ASSET,
                                     "amount": f"{svc['price_usd']:.2f}", "payTo": PAYTO_ADDRESS},
                "note": f"Pay {svc['price_usd']:.2f} USDC, then call again with the payment proof. Instant, signed result on payment."}
    try:
        return run_auto(service, subject)
    except GuardrailBlock as g:
        return {"error": g.code, "message": g.message}
    except ValueError as e:
        return {"error": str(e)}

@_mcp.tool
def notarize(content: str = "", sha256: str = "", payment: str = "") -> dict:
    """Instantly notarize content: get an ed25519-signed proof it existed at this time. Free — no payment required.
    Provide 'content' to hash (only the hash is stored, never the raw content), or a 64-char hex 'sha256'.
    payment: your x402 proof. Omit to receive payment requirements first. Proves existence at time T, not authorship."""
    return _auto_tool("notarize", {"content": content, "sha256": sha256}, payment)

@_mcp.tool
def domain_check(domain: str, payment: str = "") -> dict:
    """Instantly verify a domain/website: does it resolve, is TLS valid, how old, registrar, reachable. Free — no payment required.
    Returns a signed verdict (confirmed/refuted/uncertain) with evidence. payment: your x402 proof; omit to get requirements first.
    Informational — 'resolves + valid cert' is not proof the business is trustworthy."""
    return _auto_tool("domain_check", {"domain": domain}, payment)

@_mcp.tool
def email_check(email: str, payment: str = "") -> dict:
    """Instantly verify an email address: syntax, MX records, disposable-domain detection, deliverability signal. Free — no payment required.
    Returns a signed verdict with evidence. payment: your x402 proof; omit to get requirements first.
    Deliverability is best-effort; a 'valid' result is not a guarantee of inbox delivery."""
    return _auto_tool("email_check", {"email": email}, payment)

@_mcp.tool
def wallet_screen(address: str, network: str = "base", payment: str = "") -> dict:
    """Instantly screen an EVM address against OFAC sanctions + on-chain activity before you pay a counterparty. Free — no payment required.
    Returns a signed verdict with risk level and evidence. network: 'base' or 'ethereum'. payment: your x402 proof; omit to get requirements first.
    Informational screening only — NOT compliance, legal, or financial advice, and not 'KYC-certified'."""
    return _auto_tool("wallet_screen", {"address": address, "network": network}, payment)

@_mcp.tool
def agent_verify(agent: str, public_key: str = "", message: str = "", signature: str = "",
                 expected_name: str = "", payment: str = "") -> dict:
    """Instantly verify another agent's identity before you trust or transact with it. Free — no payment required.
    agent: the other agent's domain (example.com) or full agent-card URL.
    Checks its A2A agent card is valid, that it controls the claimed domain (DNS/TLS/host match), and — if you pass
    public_key + message + signature — cryptographically verifies it controls its key. expected_name: optional name to match.
    Returns a signed verdict (confirmed/refuted/uncertain) with evidence. payment: your x402 proof; omit to get requirements first."""
    return _auto_tool("agent_verify", {"agent": agent, "public_key": public_key, "message": message,
                                       "signature": signature, "expected_name": expected_name}, payment)

_mcp_app = _mcp.http_app(path="/mcp")   # internal route is exactly /mcp (no trailing-slash redirect)

@asynccontextmanager
async def _app_lifespan(app):
    # Background tasks: metrics flush (always) + Moltbook poller (if configured), alongside MCP lifespan.
    tasks = [asyncio.create_task(_metrics_flush_loop())]
    if MOLTBOOK_API_KEY:
        tasks.append(asyncio.create_task(_moltbook_poll_loop()))
    async with _mcp_app.lifespan(app):
        yield
    try:
        _flush_metrics()   # final flush on shutdown
    except Exception:
        pass
    for t in tasks:
        t.cancel()

app = FastAPI(title=BRAND, version="0.2.0", lifespan=_app_lifespan)
# Attach the MCP route(s) directly (instead of app.mount) so /mcp works without a redirect.
for _r in _mcp_app.routes:
    app.router.routes.append(_r)

@app.middleware("http")
async def _traffic_metrics_mw(request, call_next):
    response = await call_next(request)
    try:
        _record_metric(request.url.path, response.status_code)
    except Exception:
        pass
    return response

@app.get("/seed", response_class=HTMLResponse)
def seed_page():
    return HTMLResponse("""<!doctype html>
<meta charset="utf-8">
<title>Attestly - Bazaar seed</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:640px;margin:6vh auto;padding:0 20px;color:#1a1a1a}
  h1{color:#2F5496;font-size:22px}
  p{color:#444;line-height:1.5}
  button{background:#2F5496;color:#fff;border:0;border-radius:8px;padding:12px 18px;font-size:15px;cursor:pointer}
  button:disabled{opacity:.6;cursor:default}
  pre{background:#0b1020;color:#cfe;padding:14px;border-radius:8px;white-space:pre-wrap;word-break:break-word;font-size:12.5px;margin-top:18px}
  code{background:#eef;padding:1px 5px;border-radius:4px}
</style>
<h1>Attestly - list on the x402 Bazaar</h1>
<p>This makes one real <code>entity_check</code> payment from your connected Coinbase Wallet to Attestly's own payout wallet. That single on-chain settlement is what registers Attestly in the x402 Bazaar. You sign a gasless authorization (no ETH needed); the USDC goes to Attestly's treasury.</p>
<p>Make sure your Coinbase Wallet holds a few dollars of USDC on <b>Base</b> first.</p>
<button id="go">Connect Coinbase Wallet and pay</button>
<pre id="log">Ready.</pre>
<script type="module">
import { createWalletClient, custom } from "https://esm.sh/viem@2";
import { base } from "https://esm.sh/viem@2/chains";
import { wrapFetchWithPayment } from "https://cdn.jsdelivr.net/npm/x402-fetch/+esm";
const el = document.getElementById("log");
const NL = String.fromCharCode(10);
const log = (m) => { el.textContent += m + NL; };
const btn = document.getElementById("go");
function pickProvider(){
  const e = window.ethereum;
  if (window.coinbaseWalletExtension) return window.coinbaseWalletExtension;
  if (e && Array.isArray(e.providers)) { const cb = e.providers.find(p => p && p.isCoinbaseWallet); if (cb) return cb; }
  return e || null;
}
btn.onclick = async () => {
  btn.disabled = true;
  try {
    const provider = pickProvider();
    if (!provider) { log("No wallet detected. Enable the Coinbase Wallet extension, then reload."); btn.disabled = false; return; }
    const accts = await provider.request({ method: "eth_requestAccounts" });
    const address = accts[0];
    log("Connected: " + address);
    try { await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x2105" }] }); }
    catch (e) { log("If prompted, switch the wallet to the Base network."); }
    const walletClient = createWalletClient({ account: address, chain: base, transport: custom(provider) });
    const payFetch = wrapFetchWithPayment(fetch, walletClient);
    log("Requesting payment - approve the signature in your Coinbase Wallet popup.");
    const res = await payFetch("/v1/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ service: "entity_check", subject: { business: "Attestly Bazaar Seed", state: "AZ" } })
    });
    const text = await res.text();
    log("HTTP " + res.status);
    log(text.slice(0, 1000));
    const pr = res.headers.get("x-payment-response");
    if (pr) log("payment-response: " + pr);
    log("");
    if (res.status === 200 && text.indexOf("unverified_manual") === -1) {
      log("Settled on-chain. Attestly should appear in the Bazaar within ~10 minutes.");
    } else if (text.indexOf("unverified_manual") !== -1) {
      log("Accepted without a real CDP settle (unverified_manual). The CDP keys may be inactive - nothing indexed.");
    } else {
      log("Payment did not complete. Read the response above.");
    }
  } catch (e) {
    log("Error: " + (e && e.message ? e.message : String(e)));
  }
  btn.disabled = false;
};
</script>""")

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": BRAND}

@app.get("/")
def manifest():
    return {
        "name": BRAND, "type": "a2a-verification-service",
        "summary": "The trust layer for AI agents: instant automated checks (wallet/sanctions, domain, email, notarization) plus human-verified attestations — all cryptographically signed (ed25519). Automated checks are free; human-verified attestations are paid in USDC via x402.",
        "public_key": PUBLIC_KEY_HEX,
        "verify_signature": "ed25519 over the canonical JSON at /v1/attestations/{id}?canonical=1",
        "payment": {"protocol": "x402", "network": PAY_NETWORK_CAIP, "asset": PAY_ASSET, "pay_to": PAYTO_ADDRESS},
        "services": {k: {"title": v["title"], "description": v["description"],
                         "price_usd": v["price_usd"], "free": v.get("price_usd", 0) <= 0}
                     for k, v in SERVICES.items()},
        "pricing": pricing_policy(),
        "how_to_use": {
            "1_request": f"POST {BASE_URL}/v1/verify  body: {{\"service\":\"entity_check\",\"subject\":{{...}}}}",
            "2_pay": "Receive HTTP 402 with payment requirements (free services skip this). Pay, then retry with header X-PAYMENT.",
            "3_poll": f"GET {BASE_URL}/v1/attestations/{{id}} until status == completed",
            "4_verify": "Verify the ed25519 signature against public_key using the canonical payload",
        },
    }

@app.get("/pricing")
def pricing():
    return pricing_policy()

@app.get("/pricing.txt", response_class=PlainTextResponse)
def pricing_txt():
    p = pricing_policy()
    lines = [f"# {BRAND} pricing (version {p['version']}, status: {p['status']})", "", p["notice"], "", "Services:"]
    for k, v in p["services"].items():
        price = "FREE" if v["free"] else f"${v['price_usd']:.2f} {p['currency']}"
        lines.append(f"- {k} ({v['type']}): {price}")
    lines += ["", "Guarantees:",
              f"- {p['guarantees']['price_lock']}",
              f"- At least {p['guarantees']['advance_notice_days']} days' notice before any price increase.",
              f"- {p['guarantees']['detect_changes']}",
              "", f"Machine-readable: GET {BASE_URL}/pricing"]
    return "\n".join(lines)

@app.get("/.well-known/attestly-pubkey")
def pubkey():
    return {"algo": "ed25519", "public_key_hex": PUBLIC_KEY_HEX}

def _svc_price(key):
    """Human-readable price label for a service: 'Free' while it's free, else 'X.XX USDC'."""
    v = SERVICES[key]
    return "Free" if v.get("price_usd", 0) <= 0 else "%.2f USDC" % v["price_usd"]

def _agent_card():
    return {
        "protocolVersion": "0.3.0",
        "name": BRAND,
        "description": "The trust layer for AI agents. Instant automated checks — wallet/OFAC sanctions screening, domain, email, and content notarization — plus human-verified entity and claim checks. Every result is a cryptographically signed (ed25519) attestation. Automated checks are free; human-verified attestations are paid in USDC via x402.",
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
             "description": "A real human confirms whether a business/entity exists and matches the details provided; returns a signed verdict with evidence. Price: %s." % _svc_price("entity_check"),
             "tags": ["verification", "kyb", "entity", "trust", "x402"],
             "examples": ["Is 'Acme Lending LLC' a registered active business in Arizona?"]},
            {"id": "claim-check", "name": "Human-verified claim check",
             "description": "A real human checks a factual claim or URL against real sources; returns confirmed/refuted/uncertain with evidence. Price: %s." % _svc_price("claim_check"),
             "tags": ["verification", "fact-check", "trust", "x402"],
             "examples": ["Verify: 'https://example.com is the official site of Example Corp.'"]},
            {"id": "wallet-screen", "name": "Wallet risk & sanctions screening (instant)",
             "description": "Instantly screen an EVM address against OFAC sanctions + on-chain activity; returns a signed risk verdict. Informational, not compliance advice. Price: %s." % _svc_price("wallet_screen"),
             "tags": ["verification", "wallet", "sanctions", "ofac", "risk", "x402", "instant"],
             "examples": ["Screen 0x1234...abcd on base before I send USDC."]},
            {"id": "domain-check", "name": "Domain & website verification (instant)",
             "description": "Instantly check whether a domain resolves, has valid TLS, its age and registrar, and reachability; returns a signed verdict. Price: %s." % _svc_price("domain_check"),
             "tags": ["verification", "domain", "website", "tls", "x402", "instant"],
             "examples": ["Is stripe.com a real, resolving site with valid TLS?"]},
            {"id": "email-check", "name": "Email verification (instant)",
             "description": "Instantly check an email's syntax, MX records, disposable-domain status, and deliverability signal; returns a signed verdict. Price: %s." % _svc_price("email_check"),
             "tags": ["verification", "email", "deliverability", "x402", "instant"],
             "examples": ["Is user@example.com a deliverable, non-disposable address?"]},
            {"id": "notarize", "name": "Content notarization (instant, FREE)",
             "description": "Instantly notarize content or a hash — an ed25519-signed proof it existed at time T. Proves existence, not authorship. FREE (no payment) — the easiest way to try Attestly.",
             "tags": ["notary", "timestamp", "hash", "proof", "x402", "instant", "free"],
             "examples": ["Notarize the SHA-256 of this agreement text."]},
            {"id": "agent-verify", "name": "Agent identity verification (instant)",
             "description": "Instantly verify another agent is who it claims: validates its A2A agent card, confirms domain control (DNS/TLS/host match), and optionally verifies ed25519 key control via a signed message. Know your counterparty agent before you trust or transact. Price: %s." % _svc_price("agent_verify"),
             "tags": ["verification", "agent", "identity", "a2a", "trust", "x402", "instant"],
             "examples": ["Verify the agent at partner-agent.com is legitimate before I delegate to it."]},
        ],
        "pricing": pricing_policy(),
    }

@app.get("/.well-known/agent.json")
@app.get("/.well-known/agent-card.json")
def agent_card():
    return _agent_card()

@app.get("/llms.txt", response_class=PlainTextResponse)
def llms_txt():
    return f"""# {BRAND}

> The trust layer for AI agents. Instant automated checks plus human-verified attestations, all cryptographically signed (ed25519). Automated checks are free; human-verified attestations are paid in USDC via the x402 protocol. Verdicts: confirmed / refuted / uncertain, with evidence and a confidence score.

## Instant automated checks (signed result in the same response)
- wallet_screen ({_svc_price('wallet_screen')}): screen an EVM address vs OFAC sanctions + on-chain activity before you pay a counterparty. Informational, not compliance advice.
- agent_verify ({_svc_price('agent_verify')}): verify another agent is who it claims — validates its A2A agent card, domain control (DNS/TLS), and optional ed25519 key control. Know your counterparty agent before you trust or transact.
- domain_check ({_svc_price('domain_check')}): does a domain resolve, valid TLS, age, registrar, reachability.
- email_check ({_svc_price('email_check')}): syntax, MX records, disposable-domain detection, deliverability signal.
- notarize (FREE): signed proof that content (or its hash) existed at time T. Existence, not authorship. No payment required — the easiest way to try Attestly.

## Human-verified checks (reviewed by a real person, usually within hours)
- entity_check (${SERVICES['entity_check']['price_usd']:.0f} USDC): confirm a business/entity exists and matches given details.
- claim_check (${SERVICES['claim_check']['price_usd']:.0f} USDC): check a factual claim or URL against real sources.

## Pricing
Introductory pricing ({PRICING_STATUS}, v{PRICING_VERSION}): intentionally low while Attestly builds a track record with early agents. Prices will rise as the service matures. The price quoted at request time is locked for that request, with at least {PRICE_CHANGE_NOTICE_DAYS} days' machine-readable notice before any change. Full terms (machine-readable): GET {BASE_URL}/pricing

## How an agent uses it
1. POST {BASE_URL}/v1/verify  body: {{"service":"wallet_screen","subject":{{"address":"0x..."}}}}
2. Receive HTTP 402 with x402 payment requirements (free services skip this). Pay in USDC, retry with header X-PAYMENT.
3. Automated services return the signed, completed attestation immediately. Human services return a job id — poll GET {BASE_URL}/v1/attestations/{{id}} until status == completed.
4. Verify the ed25519 signature against the public key in the manifest.
Or call the hosted MCP server at {BASE_URL}/mcp (tools: wallet_screen, agent_verify, domain_check, email_check, notarize, request_verification, get_attestation, get_services).

## Links
- Pricing (JSON): {BASE_URL}/pricing
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
def verify(req: VerifyRequest, request: Request, x_payment: str | None = Header(default=None)):
    if req.service not in SERVICES:
        raise HTTPException(400, f"unknown service '{req.service}'. See GET / for options.")
    # Per-IP rate limit (behind Render's proxy, prefer the forwarded client IP).
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (request.client.host if request.client else "?"))
    if not _rate_ok(ip):
        return JSONResponse(status_code=429, content={
            "error": "rate_limited", "message": f"Max {RATE_PER_MIN} requests/min per caller. Slow down and retry."})
    accepted, pay_status, tx_ref = check_payment(x_payment, req.service)
    if not accepted:
        return x402_challenge(req.service)
    # Automated services run synchronously and return a signed, completed attestation now.
    if SERVICES[req.service].get("auto"):
        try:
            return run_auto(req.service, req.subject, payment_status=pay_status, payment_ref=tx_ref)
        except GuardrailBlock as g:
            return JSONResponse(status_code=g.status, content={"error": g.code, "message": g.message})
        except ValueError as e:
            raise HTTPException(400, str(e))
    att_id = "at_" + secrets.token_hex(8)
    with closing(db()) as conn:
        conn.execute("INSERT INTO attestations (id,service,subject,status,payment_ref,payment_status,created_at) VALUES (?,?,?,?,?,?,?)",
                     (att_id, req.service, json.dumps(req.subject), "pending",
                      (tx_ref or (x_payment or "")[:80]), pay_status, now_iso()))
        conn.commit()
    notify_new_job(att_id, req.service)
    if pay_status == "verified":
        notify_paid(att_id, req.service, tx_ref)
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

# ---- The file: an agent's accumulated track record (the bureau "pull") ----
@app.get("/v1/profile/{subject_key:path}")
def profile(subject_key: str):
    """Pull the accumulated history Attestly holds on a subject (wallet / agent / domain / email).
    This is the bureau file — thin today, deepening every time the subject is checked.
    Informational signals over time, not a guarantee or a compliance clearance."""
    key = (subject_key or "").strip().lower()
    with closing(db()) as conn:
        rows = conn.execute("SELECT * FROM agent_records WHERE subject_key=? ORDER BY created_at", (key,)).fetchall()
    if not rows:
        return {"subject": key, "records": 0,
                "note": "No history yet — Attestly builds a track record as this subject is checked over time."}
    by_service = {}
    for r in rows:
        by_service.setdefault(r["service"], []).append(r)
    latest = {svc: {"latest_verdict": rs[-1]["verdict"], "confidence": rs[-1]["confidence"],
                    "checks": len(rs), "last_seen": rs[-1]["created_at"]}
              for svc, rs in by_service.items()}
    return {"subject": key, "subject_type": rows[0]["subject_type"], "records": len(rows),
            "first_seen": rows[0]["created_at"], "last_seen": rows[-1]["created_at"],
            "by_service": latest,
            "note": "Point-in-time signals accumulated over time, not a guarantee. History deepens with use."}

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

@app.get("/admin/facilitator")
def admin_facilitator(x_admin_token: str | None = Header(default=None)):
    """Smoke-test the payment facilitator (auth + connectivity) WITHOUT any payment."""
    require_admin(x_admin_token)
    info = {
        "x402_lib_loaded": _X402_OK,
        "network_caip": PAY_NETWORK_CAIP,
        "network_is_mainnet": PAY_NETWORK_CAIP == "eip155:8453",
        "facilitator_url": _FAC_URL,
        "cdp_keys_present": bool(CDP_API_KEY_ID and CDP_API_KEY_SECRET),
        "facilitator_active": facilitator_active(),
        "manual_fallback_on": ALLOW_UNVERIFIED,
        "asset": _X402_ASSET if _X402_OK else None,
        "mode": "REAL verify+settle" if facilitator_active() else "manual (no real settlement yet)",
    }
    # Live authenticated call — proves keys + auth + endpoint reachability.
    if facilitator_active():
        try:
            sup = _facilitator().get_supported()
            kinds = getattr(sup, "kinds", None) or getattr(sup, "supported", None) or sup
            info["get_supported_ok"] = True
            info["supported_sample"] = str(kinds)[:500]
        except Exception as e:
            info["get_supported_ok"] = False
            info["error"] = f"{type(e).__name__}: {str(e)[:300]}"
    return info

@app.get("/admin/metrics")
def admin_metrics(x_admin_token: str | None = Header(default=None)):
    """Traffic to discovery + intent endpoints — who's looking, and who's hitting the paywall."""
    require_admin(x_admin_token)
    _flush_metrics()
    with closing(db()) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS metrics (day TEXT, label TEXT, count INTEGER, PRIMARY KEY(day,label))")
        rows = conn.execute("SELECT day,label,count FROM metrics").fetchall()
    today = now_iso()[:10]
    week = {(datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat() for i in range(7)}
    all_time, last7, today_c = defaultdict(int), defaultdict(int), defaultdict(int)
    for r in rows:
        all_time[r["label"]] += r["count"]
        if r["day"] in week: last7[r["label"]] += r["count"]
        if r["day"] == today: today_c[r["label"]] += r["count"]
    return {"today": dict(today_c), "last_7_days": dict(last7), "all_time": dict(all_time),
            "note": "Counts include bots/scanners. Strongest real-agent-intent signals: 'mcp' (agent connected) and 'verify_payment_prompt' (hit the paywall)."}

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

@app.get("/admin/profiles")
def admin_profiles(x_admin_token: str | None = Header(default=None)):
    """The data asset growing: how many bureau rows, how many distinct subjects, and the most-checked."""
    require_admin(x_admin_token)
    with closing(db()) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS agent_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject_key TEXT NOT NULL, subject_type TEXT NOT NULL,
            service TEXT NOT NULL, verdict TEXT, confidence INTEGER, summary TEXT,
            facts TEXT, attestation_id TEXT, payment_status TEXT, created_at TEXT NOT NULL)""")
        total = conn.execute("SELECT COUNT(*) c FROM agent_records").fetchone()["c"]
        subjects = conn.execute("SELECT COUNT(DISTINCT subject_key) c FROM agent_records").fetchone()["c"]
        by_type = conn.execute("SELECT subject_type, COUNT(DISTINCT subject_key) c FROM agent_records GROUP BY subject_type").fetchall()
        top = conn.execute("SELECT subject_key, subject_type, COUNT(*) n, MIN(created_at) f, MAX(created_at) l "
                           "FROM agent_records GROUP BY subject_key ORDER BY n DESC LIMIT 50").fetchall()
    return {"total_records": total, "distinct_subjects": subjects,
            "subjects_by_type": {r["subject_type"]: r["c"] for r in by_type},
            "top_subjects": [{"subject": r["subject_key"], "type": r["subject_type"], "checks": r["n"],
                              "first_seen": r["f"], "last_seen": r["l"]} for r in top],
            "note": "This is the memory. It compounds every time a subject is checked — the moat a competitor can't backfill."}

@app.get("/admin/guardrails")
def admin_guardrails(x_admin_token: str | None = Header(default=None)):
    """Cost/abuse guardrail status — confirm free can't turn into expensive or abused."""
    require_admin(x_admin_token)
    return {"auto_checks_enabled": AUTO_CHECKS_ENABLED, "all_auto_free": ALL_AUTO_FREE,
            "free_daily_ceiling": FREE_DAILY_CEILING, "today": _DAILY.get("day"),
            "today_auto_count": _DAILY.get("count", 0), "rate_per_min": RATE_PER_MIN,
            "cache_ttl_min": CACHE_TTL_MIN, "cache_entries": len(_AUTO_CACHE),
            "spike_alert_at": SPIKE_ALERT_AT,
            "note": "No automated check calls a paid per-request API — a spike is load on a fixed box, not a bill. "
                    "Kill-switch: set AUTO_CHECKS_ENABLED=false."}

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
        <div style="font-size:22px;font-weight:700;color:#2F5496">{'Free' if v.get('price_usd',0)<=0 else '$'+format(v['price_usd'],'.2f')}<span style="font-size:13px;color:#888;font-weight:400"> {'· try it' if v.get('price_usd',0)<=0 else '/ check'}</span></div>
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
      plus <b>human-verified attestations</b> for the calls that need judgment. <b>Automated checks are free</b>; human-verified
      attestations are paid in USDC. Every result is cryptographically signed — verify it yourself.</p>

      <h3 style="margin-top:34px">Instant automated checks</h3>
      <p style="color:#666;margin-top:2px">Signed result in the same response — no waiting, no human.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin:14px 0 30px">{auto_cards}</div>

      <h3>Human-verified checks</h3>
      <p style="color:#666;margin-top:2px">A real person verifies against primary sources — for the calls automation can't make.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin:14px 0 8px">{human_cards}</div>
      <div style="display:inline-block;background:#eaf1fb;color:#2F5496;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:3px 8px;border-radius:999px">Introductory pricing</div>
      <p style="color:#666;font-size:13.5px;margin:10px 0 0">All automated checks are free right now. The human-verified checks use introductory rates — intentionally low while we build a track record — and prices will rise as the service matures, always with advance notice, with the price quoted when your agent calls locked for that request. <a href="/pricing" style="color:#2F5496">Full pricing terms →</a></p>

      <h3 style="margin-top:32px">How it works</h3>
      <ol><li>Your agent calls <code>POST /v1/verify</code> (or the hosted MCP server at <code>/mcp</code>) — automated checks are free; human-verified checks are paid via x402 (USDC).</li>
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
  <button onclick=loadTraffic() style="padding:8px 14px">Traffic</button>
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
const METRIC_LABELS={mcp:'🔌 MCP connects/calls (agent intent)',verify_payment_prompt:'💳 Paywall hits · 402 (buying intent)',verify_completed:'✅ Checks completed',manifest:'📄 Manifest views (/)',agent_card:'🪪 Agent card views',llms_txt:'📜 llms.txt views',pricing:'🏷️ Pricing views',home:'🏠 Landing page views',attestation_view:'🔎 Public result-page views',attestation_api:'📥 Attestation API reads',pubkey:'🔑 Public key fetches'};
const METRIC_ORDER=['mcp','verify_payment_prompt','verify_completed','manifest','agent_card','llms_txt','pricing','home','attestation_view','attestation_api','pubkey'];
async function loadTraffic(){
  document.getElementById('msg').textContent='loading traffic...';
  document.getElementById('legend').style.display='none';
  document.getElementById('stats').innerHTML='';
  const r=await fetch('/admin/metrics',{headers:H()});
  if(!r.ok){document.getElementById('msg').textContent='error '+r.status;return;}
  const m=await r.json();
  const keys=[...new Set([...METRIC_ORDER,...Object.keys(m.all_time||{})])].filter(k=>(m.all_time||{})[k]!=null);
  document.getElementById('msg').textContent='traffic';
  let rows=keys.map(k=>{const lbl=METRIC_LABELS[k]||k;
    return `<tr><td style="padding:6px 14px 6px 0">${lbl}</td>
      <td style="text-align:right;padding:6px 14px;font-weight:700">${(m.today||{})[k]||0}</td>
      <td style="text-align:right;padding:6px 14px;font-weight:700">${(m.last_7_days||{})[k]||0}</td>
      <td style="text-align:right;padding:6px 0;color:#666">${(m.all_time||{})[k]||0}</td></tr>`;}).join('');
  if(!rows) rows='<tr><td style="padding:8px;color:#888">No traffic recorded yet.</td></tr>';
  document.getElementById('list').innerHTML=
    `<h3 style="margin:6px 0">Traffic — who's looking</h3>
     <table style="border-collapse:collapse;font-size:14px;margin:6px 0 12px">
       <tr style="color:#888;font-size:12px;text-transform:uppercase"><td style="padding:0 14px 4px 0">Endpoint</td><td style="text-align:right;padding:0 14px">Today</td><td style="text-align:right;padding:0 14px">7 days</td><td style="text-align:right">All-time</td></tr>
       ${rows}
     </table>
     <div style="font-size:12.5px;color:#555;background:#f6f8fc;border:1px solid #e2e8f5;border-radius:8px;padding:10px 12px;max-width:640px">
       Counts include bots &amp; scanners. The two rows that signal a <b>real agent with intent</b> are <b>🔌 MCP connects</b> (an agent wired you into its toolset) and <b>💳 Paywall hits (402)</b> (an agent called a paid check and got the payment challenge). Discovery views (manifest, agent card, llms.txt) show you're being <i>found</i>; MCP + 402 show you're being <i>used</i>.
     </div>`;
}
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
