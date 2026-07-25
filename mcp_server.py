"""
Attestly MCP server — exposes Attestly's human-verification service as MCP tools,
so any MCP-capable AI agent can discover and call it.

It's a thin client over the live Attestly API (default https://attestly.co). Set
ATTESTLY_BASE_URL to point elsewhere.

Run (stdio, the standard transport):
    pip install mcp httpx
    python mcp_server.py

Add to an MCP client (e.g. Claude Desktop) config:
    {
      "mcpServers": {
        "attestly": { "command": "python", "args": ["/path/to/mcp_server.py"] }
      }
    }
"""

import os
import httpx
from mcp.server.fastmcp import FastMCP

BASE = os.environ.get("ATTESTLY_BASE_URL", "https://attestly.co").rstrip("/")

mcp = FastMCP("attestly")


@mcp.tool()
def get_services() -> dict:
    """List Attestly's verification services, their prices (USDC), and how payment works."""
    r = httpx.get(f"{BASE}/", timeout=20)
    r.raise_for_status()
    m = r.json()
    return {"services": m.get("services"), "payment": m.get("payment"), "how_to_use": m.get("how_to_use")}


@mcp.tool()
def request_verification(service: str, subject: dict, payment: str = "") -> dict:
    """
    Ask a real human to verify a fact or an entity, returned as a signed attestation.

    service: "entity_check" (does this business/entity exist & match?) or
             "claim_check" (is this factual claim/URL true?).
    subject: what to verify, e.g. {"business":"Acme LLC","state":"AZ","claim":"is registered"}.
    payment: your x402 payment proof. Leave empty to first receive the exact payment
             requirements (amount, asset, payTo); then pay and call again with the proof.

    Returns either x402 payment requirements (if unpaid) or an attestation_id you can poll.
    """
    headers = {"X-PAYMENT": payment} if payment else {}
    r = httpx.post(f"{BASE}/v1/verify", json={"service": service, "subject": subject},
                   headers=headers, timeout=30)
    try:
        return r.json()
    except Exception:
        return {"status_code": r.status_code, "text": r.text[:500]}


@mcp.tool()
def get_attestation(attestation_id: str) -> dict:
    """Fetch an attestation by id: its status, and (when completed) the signed verdict,
    evidence, confidence, signature, and public key so you can verify it yourself."""
    r = httpx.get(f"{BASE}/v1/attestations/{attestation_id}", timeout=20)
    return r.json()


if __name__ == "__main__":
    mcp.run()
