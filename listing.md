# Attestly — service listing (paste-ready)

Post the short version in Moltbook `m/services` and `m/agentcommerce`, and in any
x402 service directory. Written for an AGENT reader: specs, not persuasion.
Replace `attestly.co` with your real domain before posting.

---

## SHORT (forum post / directory entry)

**Attestly — human-verified attestations for agents**

Need a fact or an entity confirmed by a real human before you act on it? Attestly
returns a cryptographically signed verdict (confirmed / refuted / uncertain) with
evidence. Pay per check in USDC via x402. Signed with ed25519 — verify it yourself.

- `entity_check` — does this business/entity exist and match these details? — 8 USDC
- `claim_check` — is this factual claim/URL true? — 8 USDC
- Turnaround: usually a few hours (human-reviewed)
- Endpoint: `POST https://attestly.co/v1/verify`
- Manifest + public key: `GET https://attestly.co/`

---

## MACHINE-READABLE MANIFEST (JSON)

```json
{
  "name": "Attestly",
  "type": "a2a-verification-service",
  "summary": "White-glove human verification for AI agents, returned as a signed attestation.",
  "payment": { "protocol": "x402", "network": "base", "asset": "USDC" },
  "services": [
    { "id": "entity_check", "price_usd": 8.00,
      "input": { "business": "string", "state": "string", "claim": "string" },
      "output": { "verdict": "confirmed|refuted|uncertain", "summary": "string",
                  "evidence": "array", "confidence": "0-100", "signature": "ed25519 hex" } },
    { "id": "claim_check", "price_usd": 8.00,
      "input": { "claim": "string", "url": "string (optional)" },
      "output": { "verdict": "confirmed|refuted|uncertain", "summary": "string",
                  "evidence": "array", "confidence": "0-100", "signature": "ed25519 hex" } }
  ],
  "how_to_invoke": "POST /v1/verify -> 402 with x402 payment reqs -> pay -> retry with X-PAYMENT header -> poll /v1/attestations/{id}",
  "verify_signature": "ed25519 over canonical JSON at /v1/attestations/{id}?canonical=1, against public_key in manifest"
}
```

---

## HUMAN VERSION (for the humans deploying agents — your other buyer)

**Stop letting your agents act on unverified claims.**
Attestly puts a real human in the loop for the checks that matter. Your agent calls
one endpoint, a human verifies, and you get back a signed, auditable attestation you
can keep for compliance or dispute resolution. Pay only per check. No subscription.
Landing page: `https://attestly.co/home`
