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
import json
import sqlite3
import secrets
from datetime import datetime, timezone
from contextlib import closing

import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse
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

SERVICES = {
    "entity_check": {
        "title": "Human-verified entity check",
        "description": "A real human confirms whether a business/entity exists and matches the details you provide, with evidence and a signed verdict.",
        "price_usd": 8.00,
    },
    "claim_check": {
        "title": "Human-verified claim check",
        "description": "A real human checks a factual claim or URL against real sources and returns confirmed / refuted / uncertain, with evidence and a signed verdict.",
        "price_usd": 8.00,
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
app = FastAPI(title=BRAND, version="0.2.0")

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": BRAND}

@app.get("/")
def manifest():
    return {
        "name": BRAND, "type": "a2a-verification-service",
        "summary": "White-glove human verification for AI agents. Pay a small fee, a real human verifies, you get a cryptographically signed attestation.",
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
    att_id = "at_" + secrets.token_hex(8)
    with closing(db()) as conn:
        conn.execute("INSERT INTO attestations (id,service,subject,status,payment_ref,payment_status,created_at) VALUES (?,?,?,?,?,?,?)",
                     (att_id, req.service, json.dumps(req.subject), "pending",
                      (x_payment or "")[:80], pay_status, now_iso()))
        conn.commit()
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

@app.get("/admin/pending")
def admin_pending(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    with closing(db()) as conn:
        rows = conn.execute("SELECT id,service,subject,payment_status,created_at FROM attestations WHERE status='pending' ORDER BY created_at").fetchall()
    return [{"id": r["id"], "service": r["service"], "subject": json.loads(r["subject"]),
             "payment_status": r["payment_status"], "created_at": r["created_at"]} for r in rows]

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
    color = {"confirmed": "#0a7d2c", "refuted": "#b00020", "uncertain": "#8a6d00"}.get(row["verdict"], "#333")
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>{BRAND} attestation {att_id}</title>
    <body style="font-family:system-ui;max-width:720px;margin:48px auto;color:#1a1a1a;line-height:1.5">
      <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#666">{BRAND} · Human-verified attestation</div>
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
    cards = "".join(
        f"""<div style="border:1px solid #e5e5e5;border-radius:12px;padding:20px;flex:1;min-width:240px">
        <div style="font-weight:700;font-size:18px">{v['title']}</div>
        <div style="color:#555;margin:8px 0">{v['description']}</div>
        <div style="font-size:22px;font-weight:700;color:#2F5496">${v['price_usd']:.0f}<span style="font-size:13px;color:#888;font-weight:400"> / check</span></div>
        </div>""" for v in SERVICES.values())
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>{BRAND}</title>
    <meta name=viewport content="width=device-width,initial-scale=1">
    <body style="font-family:system-ui;max-width:860px;margin:0 auto;padding:48px 20px;color:#1a1a1a;line-height:1.55">
      <div style="font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:#2F5496;font-weight:700">{BRAND}</div>
      <h1 style="font-size:40px;margin:.1em 0 .2em">Human verification for AI agents.</h1>
      <p style="font-size:20px;color:#444">Your agent can pay software, but it can't buy trustworthy human judgment.
      {BRAND} puts a real person in the loop: pay per check in USDC, a human verifies, and you get back a
      cryptographically signed attestation you can verify and keep.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin:28px 0">{cards}</div>
      <h3>How it works</h3>
      <ol><li>Your agent calls <code>POST /v1/verify</code> and pays via x402 (USDC).</li>
      <li>A real human verifies against primary sources.</li>
      <li>You get a signed verdict (confirmed / refuted / uncertain) with evidence.</li>
      <li>Anyone can verify the signature — trust, provable.</li></ol>
      <p style="margin-top:28px"><a href="/" style="color:#2F5496">Agent manifest (JSON)</a> ·
      <a href="mailto:{CONTACT_EMAIL}" style="color:#2F5496">Contact</a></p>
      <p style="color:#999;font-size:13px;margin-top:40px">{BRAND} verifies facts and entities. It does not provide legal, medical, or financial advice.</p>
    </body>""")

# ---- Admin console (browser) ----
@app.get("/admin", response_class=HTMLResponse)
def admin_console():
    return HTMLResponse("""<!doctype html><meta charset=utf-8><title>Attestly admin</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<body style="font-family:system-ui;max-width:820px;margin:0 auto;padding:32px 18px;color:#1a1a1a">
<h1 style="color:#2F5496">Attestly — fulfillment console</h1>
<p>Enter your admin token, load pending jobs, verify each against real sources, then sign & publish.</p>
<div style="margin:12px 0">
  <input id=tok type=password placeholder="admin token" style="padding:8px;width:280px">
  <button onclick=load() style="padding:8px 14px">Load pending</button>
  <span id=msg style="margin-left:10px;color:#666"></span>
</div>
<div id=list></div>
<script>
const H=()=>({'X-ADMIN-TOKEN':document.getElementById('tok').value,'content-type':'application/json'});
async function load(){
  document.getElementById('msg').textContent='loading...';
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
