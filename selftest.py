import os, json
os.environ.update(ADMIN_TOKEN="test-secret", PAYTO_ADDRESS="0xTESTWALLET",
                  BASE_URL="http://localhost:8000", ALLOW_UNVERIFIED_PAYMENTS="true",
                  ATTESTLY_DB="/tmp/selftest.db", ATTESTLY_KEY="/tmp/selftest_key.hex")
for f in ("/tmp/selftest.db", "/tmp/selftest_key.hex"):
    if os.path.exists(f): os.remove(f)

from fastapi.testclient import TestClient
import app as A
c = TestClient(A.app)

ok = True
def check(label, cond):
    global ok; ok = ok and cond
    print(("PASS " if cond else "FAIL ") + label)

for p in ["/healthz", "/", "/home", "/admin", "/.well-known/attestly-pubkey"]:
    check(f"GET {p} 200", c.get(p).status_code == 200)

r = c.post("/v1/verify", json={"service": "entity_check", "subject": {"business": "Acme LLC", "state": "AZ"}})
check("POST /v1/verify -> 402 without payment", r.status_code == 402)
check("402 body has x402 accepts+payTo", r.json()["accepts"][0]["payTo"] == "0xTESTWALLET")

r = c.post("/v1/verify", json={"service": "entity_check", "subject": {"business": "Acme LLC", "state": "AZ"}},
           headers={"X-PAYMENT": "demo-proof"})
check("POST /v1/verify -> 200 with payment", r.status_code == 200)
aid = r.json().get("attestation_id")
check("payment flagged unverified_manual", r.json().get("payment_status") == "unverified_manual")

r = c.get("/admin/pending", headers={"X-ADMIN-TOKEN": "test-secret"})
check("admin/pending lists the job", r.status_code == 200 and any(j["id"] == aid for j in r.json()))
check("admin/pending rejects bad token", c.get("/admin/pending", headers={"X-ADMIN-TOKEN": "wrong"}).status_code == 401)

r = c.post(f"/admin/attestations/{aid}/complete",
           json={"verdict": "confirmed", "summary": "Acme LLC is active in AZ.", "confidence": 95,
                 "evidence": [{"label": "AZCC", "url": "https://ecorp.azcc.gov"}]},
           headers={"X-ADMIN-TOKEN": "test-secret"})
check("complete (sign+publish) -> 200", r.status_code == 200)

full = c.get(f"/v1/attestations/{aid}").json()
canon = c.get(f"/v1/attestations/{aid}?canonical=1").json()
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
try:
    VerifyKey(full["public_key"], encoder=HexEncoder).verify(payload, bytes.fromhex(full["signature"]))
    check("ed25519 signature verifies independently", True)
except Exception as e:
    check(f"ed25519 signature verifies ({e})", False)

check("public page shows verdict", "Confirmed".lower() in c.get(f"/a/{aid}").text.lower())

# facilitator mode: without a facilitator + ALLOW_UNVERIFIED false, must 402
import importlib
os.environ["ALLOW_UNVERIFIED_PAYMENTS"] = "false"
os.environ["FACILITATOR_URL"] = ""
importlib.reload(A)
c2 = TestClient(A.app)
r = c2.post("/v1/verify", json={"service": "entity_check", "subject": {"x": 1}}, headers={"X-PAYMENT": "demo"})
check("safe default: no facilitator + no-unverified -> 402", r.status_code == 402)

print("\nALL PASS ✓" if ok else "\nSOME FAILED ✗")
