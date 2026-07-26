import os, json, hashlib
os.environ.update(ADMIN_TOKEN="test-secret", PAYTO_ADDRESS="0xTESTWALLET",
                  BASE_URL="http://localhost:8000", ALLOW_UNVERIFIED_PAYMENTS="true",
                  ATTESTLY_DB="/tmp/selftest_auto.db", ATTESTLY_KEY="/tmp/selftest_auto_key.hex")
for f in ("/tmp/selftest_auto.db", "/tmp/selftest_auto_key.hex"):
    if os.path.exists(f): os.remove(f)

from fastapi.testclient import TestClient
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
import app as A

ok = True
def check(label, cond):
    global ok; ok = ok and cond
    print(("PASS " if cond else "FAIL ") + label)

PAY = {"X-PAYMENT": "demo-proof"}

def verify_sig(att_id):
    """Fetch canonical payload + signature, verify ed25519 independently (re-serialize canonically)."""
    full = c.get(f"/v1/attestations/{att_id}").json()
    canon = c.get(f"/v1/attestations/{att_id}?canonical=1").json()
    payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
    VerifyKey(full["public_key"], encoder=HexEncoder).verify(payload, bytes.fromhex(full["signature"]))
    return full

with TestClient(A.app) as c:
    # --- payment gating: automated service returns 402 without payment ---
    r = c.post("/v1/verify", json={"service": "notarize", "subject": {"content": "hello"}})
    check("auto service -> 402 without payment", r.status_code == 402)

    # --- notarize: deterministic, verify hash + signature ---
    content = "The quick brown fox."
    expected = hashlib.sha256(content.encode()).hexdigest()
    r = c.post("/v1/verify", json={"service": "notarize", "subject": {"content": content}}, headers=PAY)
    check("notarize -> 200 completed", r.status_code == 200 and r.json().get("status") == "completed")
    body = r.json()
    check("notarize verdict=notarized", body.get("verdict") == "notarized")
    check("notarize hash correct", body.get("data", {}).get("sha256") == expected)
    check("notarize does NOT store raw content", "content" not in json.dumps(body.get("data", {})).lower() or body["data"].get("sha256") == expected and "content" not in body["data"])
    check("notarize signature verifies independently", bool(verify_sig(body["attestation_id"])))

    # --- notarize accepts a raw sha256 too ---
    r = c.post("/v1/verify", json={"service": "notarize", "subject": {"sha256": expected}}, headers=PAY)
    check("notarize accepts raw sha256", r.status_code == 200 and r.json()["data"]["sha256"] == expected)

    # --- notarize rejects bad input ---
    r = c.post("/v1/verify", json={"service": "notarize", "subject": {"sha256": "nothex"}}, headers=PAY)
    check("notarize rejects bad sha256 -> 400", r.status_code == 400)

    # --- domain_check: structure + signature (network-dependent values) ---
    r = c.post("/v1/verify", json={"service": "domain_check", "subject": {"domain": "example.com"}}, headers=PAY)
    check("domain_check -> 200 completed", r.status_code == 200 and r.json().get("status") == "completed")
    d = r.json()
    check("domain_check verdict valid", d.get("verdict") in ("confirmed", "refuted", "uncertain"))
    check("domain_check data has fields", set(["domain", "resolves", "ssl_valid", "http_status"]).issubset(d.get("data", {}).keys()))
    check("domain_check signature verifies", bool(verify_sig(d["attestation_id"])))

    # --- domain_check rejects junk ---
    r = c.post("/v1/verify", json={"service": "domain_check", "subject": {"domain": "notadomain"}}, headers=PAY)
    check("domain_check rejects no-dot input -> 400", r.status_code == 400)

    # --- email_check: valid syntax + disposable + bad syntax ---
    r = c.post("/v1/verify", json={"service": "email_check", "subject": {"email": "not-an-email"}}, headers=PAY)
    check("email_check bad syntax -> refuted", r.status_code == 200 and r.json().get("verdict") == "refuted")

    r = c.post("/v1/verify", json={"service": "email_check", "subject": {"email": "someone@mailinator.com"}}, headers=PAY)
    check("email_check disposable flagged", r.status_code == 200 and r.json()["data"].get("disposable") is True)

    r = c.post("/v1/verify", json={"service": "email_check", "subject": {"email": "hi@example.com"}}, headers=PAY)
    check("email_check signature verifies", bool(verify_sig(r.json()["attestation_id"])))

    # --- wallet_screen: address validation, structure, sanctions field ---
    r = c.post("/v1/verify", json={"service": "wallet_screen", "subject": {"address": "0xdeadbeef"}}, headers=PAY)
    check("wallet_screen rejects bad address -> 400", r.status_code == 400)

    good = "0x388C818CA8B9251b393131C08a736A67ccB19297"  # arbitrary valid-format EVM addr
    r = c.post("/v1/verify", json={"service": "wallet_screen", "subject": {"address": good, "network": "base"}}, headers=PAY)
    check("wallet_screen -> 200 completed", r.status_code == 200 and r.json().get("status") == "completed")
    w = r.json()
    check("wallet_screen has risk_level + sanctioned", set(["sanctioned", "risk_level", "flags"]).issubset(w.get("data", {}).keys()))
    check("wallet_screen signature verifies", bool(verify_sig(w["attestation_id"])))

    # --- MCP tools registered ---
    import asyncio
    tools = asyncio.run(A._mcp.list_tools())
    names = set(t.name for t in tools)
    check("MCP tools include 4 auto + human tools",
          {"notarize", "domain_check", "email_check", "wallet_screen", "request_verification", "get_services"}.issubset(names))

    # --- manifest + llms.txt + agent card reflect all 6 services ---
    man = c.get("/").json()
    check("manifest lists all 6 services", set(man["services"].keys()) == set(A.SERVICES.keys()))
    llms = c.get("/llms.txt").text
    check("llms.txt mentions wallet_screen", "wallet_screen" in llms)
    ac = c.get("/.well-known/agent.json").json()
    check("agent card has >=6 skills", len(ac.get("skills", [])) >= 6)
    check("home page renders 200", c.get("/home").status_code == 200)

print("\n" + ("ALL PASS ✓" if ok else "SOME FAILED ✗"))
import sys; sys.exit(0 if ok else 1)
