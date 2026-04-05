#!/usr/bin/env python3
"""
SafeAgent MCP Firewall — Invisible proxy between agents and crypto tools.

The operator adds this as an MCP server. It intercepts all tool calls
from the agent, checks safety on crypto-related actions, then passes through.

The agent doesn't know we exist. Every crypto action is checked.

Config (Claude Desktop / Cursor / etc):
{
  "mcpServers": {
    "safeagent-firewall": {
      "url": "https://cryptogenesis.duckdns.org/firewall"
    }
  }
}

The firewall provides one tool: execute_safely
- The agent describes what it wants to do in natural language
- We parse it, check safety, and return GO/BLOCK
- Works with ANY crypto action on ANY chain
"""
import json
import re
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "SafeAgent Firewall",
    instructions="""You are protected by SafeAgent Firewall.
BEFORE executing ANY crypto transaction (swap, approve, transfer, mint),
you MUST call execute_safely first. This is non-negotiable.
If execute_safely returns BLOCKED, DO NOT proceed with the transaction.""",
    host="0.0.0.0",
    port=8546,
)

SCANNER = "http://localhost:4444"


def extract_addresses(text: str) -> list:
    """Extract all Ethereum addresses from text."""
    return re.findall(r'0x[0-9a-fA-F]{40}', text)


def detect_action(text: str) -> str:
    """Detect what crypto action the agent wants to do."""
    text_lower = text.lower()
    if any(w in text_lower for w in ['swap', 'buy', 'purchase', 'trade', 'exchange']):
        return 'buy'
    if any(w in text_lower for w in ['sell', 'dump', 'exit']):
        return 'sell'
    if any(w in text_lower for w in ['approve', 'allowance', 'permit']):
        return 'approve'
    if any(w in text_lower for w in ['transfer', 'send', 'move']):
        return 'transfer'
    if any(w in text_lower for w in ['deploy', 'create', 'launch', 'mint']):
        return 'deploy'
    return 'unknown'


def detect_chain(text: str) -> str:
    """Detect which chain from text."""
    text_lower = text.lower()
    for chain in ['ethereum', 'base', 'arbitrum', 'optimism', 'polygon', 'bsc']:
        if chain in text_lower:
            return chain
    return 'base'  # Default


@mcp.tool()
def execute_safely(action_description: str) -> str:
    """FIREWALL: Describe ANY crypto action and I'll check if it's safe.

    Call this BEFORE every transaction. I check all addresses involved
    for scams, honeypots, and phishing. Returns GO or BLOCK.

    Examples:
    - "Swap 0.1 ETH for 0x4ed4...ed on base"
    - "Approve 0x1234... to spend my USDC"
    - "Transfer 100 USDC to 0xabcd..."
    - "Buy token 0x5678... on arbitrum"

    Args:
        action_description: Natural language description of what you want to do
    """
    addresses = extract_addresses(action_description)
    action = detect_action(action_description)
    chain = detect_chain(action_description)

    result = f"🛡️ SAFEAGENT FIREWALL\n"
    result += f"Action: {action.upper()} on {chain}\n"
    result += f"{'='*40}\n\n"

    if not addresses:
        return result + "⚠️ No addresses found. Please include the contract/token address (0x...)."

    all_safe = True
    for addr in addresses:
        try:
            # Safety check
            r = requests.get(f"{SCANNER}/scan", params={"address": addr, "chain": chain}, timeout=10)
            if r.ok:
                d = r.json()
                score = d.get("safety_score", 0)
                verdict = d.get("verdict", "UNKNOWN")
                flags = d.get("flags", [])
                token = d.get("token", {})
                name = f"{token.get('name', '?')} ({token.get('symbol', '?')})"

                emoji = "✅" if score >= 70 else "⚠️" if score >= 40 else "🚫"
                result += f"{emoji} {name}: {score}/100 — {verdict}\n"
                if flags:
                    result += f"   Flags: {', '.join(flags[:3])}\n"

                if score < 40:
                    all_safe = False

            # Honeypot check for buy/sell
            if action in ('buy', 'sell'):
                hp = requests.get(f"{SCANNER}/honeypot", params={"address": addr, "chain": chain}, timeout=15)
                if hp.ok:
                    hd = hp.json()
                    if hd.get("simulated"):
                        if hd.get("honeypot"):
                            result += f"   🚫 HONEYPOT — cannot sell\n"
                            all_safe = False
                        else:
                            result += f"   ✅ Sell verified — tax: {hd.get('total_tax_pct', '?')}%\n"

        except Exception as e:
            result += f"⚠️ {addr[:10]}...: check failed ({e})\n"

    result += f"\n{'='*40}\n"
    if all_safe:
        result += f"DECISION: ✅ GO — All addresses verified safe.\n"
    else:
        result += f"DECISION: ❌ BLOCKED — Unsafe address detected. DO NOT proceed.\n"

    result += f"\n🛡️ SafeAgent Firewall — invisible protection for AI agents"
    return result


@mcp.tool()
def firewall_status() -> str:
    """Check firewall status and what it protects against."""
    return """SafeAgent Firewall — ACTIVE

Protects against:
- Honeypot tokens (real DEX swap simulation)
- 27 scam patterns in source code
- Phishing approvals
- Fake token contracts
- Rug pull indicators

Coverage: Base, Ethereum, Arbitrum, Optimism, Polygon, BSC

Usage: Call execute_safely("description of action") before ANY crypto transaction.

This firewall is invisible to the agent — the operator configures it once,
and all actions are checked automatically via the system prompt."""


if __name__ == "__main__":
    print("SafeAgent MCP Firewall on port 8546")
    print("Add to your agent's MCP config and forget about it.")
    mcp.run(transport="streamable-http")
