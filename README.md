# ERC Token Safety Score

**The open standard for token safety scoring on EVM chains.**

Any smart contract, wallet, DEX, or AI agent can query whether a token is safe — using a single, standardized interface.

## The Problem

- Billions lost annually to scam tokens (honeypots, rug pulls, hidden mints)
- No standard exists for token safety — every tool uses proprietary scoring
- AI agents trading autonomously have no way to check safety before buying
- Smart contracts cannot gate interactions based on safety data

## The Standard

ERC Token Safety Score defines:

- **Score 0-100** — universal safety rating for any ERC-20 token
- **16 risk flags** — bitmask identifying specific risks (honeypot, hidden mint, blacklist, etc.)
- **On-chain interface** — `getSafetyScore(address token)` and `isSafe(address token, uint8 minScore)`
- **Off-chain metadata** — JSON schema for detailed safety reports
- **AI agent discovery** — `.well-known/token-safety-oracle.json` endpoint

```solidity
interface IERC_TokenSafetyScore {
    function getSafetyScore(address token) 
        external view returns (uint8 score, uint256 flags, uint256 updatedAt);
    
    function isSafe(address token, uint8 minScore) 
        external view returns (bool safe);
}
```

## Live Oracle

Deployed and operational on **Optimism mainnet**:

| | |
|---|---|
| **Contract** | [`0x3B8A6D696f2104A9aC617bB91e6811f489498047`](https://optimistic.etherscan.io/address/0x3B8A6D696f2104A9aC617bB91e6811f489498047) |
| **Chain** | Optimism (Chain ID: 10) |
| **Tokens scored** | 9 major tokens (WETH, OP, USDC, USDT, DAI, VELO, wstETH, rETH, SNX, LINK) |
| **Gas cost per query** | ~0 (view function) |

## SafeAgent MCP Server

AI agents can query token safety via the **Model Context Protocol**:

```
MCP SSE: https://cryptogenesis.duckdns.org/mcp/sse
REST API: https://cryptogenesis.duckdns.org/token/scan?address=0x...&chain=base
```

### Tools

| Tool | Description |
|------|-------------|
| `check_token_safety` | Full safety analysis — honeypot detection, 17 scam patterns, LP lock check. 6 EVM chains. |
| `get_defi_yields` | Top DeFi yields with quality grades (A-F), 17K+ pools across 30+ chains |
| `get_market_overview` | DeFi market analysis with TVL breakdown and risk alerts |

### Supported Chains

Base, Ethereum, Arbitrum, Optimism, Polygon, BSC

## Detection Capabilities

| Check | Method |
|-------|--------|
| Honeypot | Simulates real buy+sell on DEX routers (UniV2, V3, Aerodrome) |
| Hidden mint | Source code pattern matching |
| Blacklist | Source code pattern matching |
| Fee manipulation | Source code pattern matching |
| Trading pause | Source code pattern matching |
| Self-destruct | Source code pattern matching |
| Proxy/upgradeable | Source code + on-chain detection |
| LP lock | Checks Unicrypt, TeamFinance, PinkSale, dead addresses |
| Owner status | Checks if ownership is renounced |
| +8 more patterns | See [ERC spec](./ERC-TokenSafetyScore.md) for full list |

## Risk Flags

Each bit in the `flags` field represents a specific risk:

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | UNVERIFIED | Source code not verified |
| 1 | HONEYPOT | Sell transactions blocked |
| 2 | HIDDEN_MINT | Owner can mint unlimited |
| 3 | BLACKLIST | Owner can blacklist addresses |
| 4 | FEE_MANIPULATION | Owner can set 100% fees |
| 5 | TRADING_PAUSE | Owner can disable trading |
| 6 | PROXY_UPGRADEABLE | Owner can change logic |
| 7 | SELF_DESTRUCT | Contract can be destroyed |
| 8 | DELEGATECALL | Arbitrary code execution |
| 9 | OWNERSHIP_NOT_RENOUNCED | Owner has privileges |
| 10 | LOW_LIQUIDITY | < $10K liquidity |
| 11 | LP_NOT_LOCKED | LP tokens not locked |
| 12 | HIGH_TAX | Tax > 10% |
| 13-15 | Reserved | Future risk categories |

## Integration

### Smart Contract

```solidity
IERC_TokenSafetyScore oracle = IERC_TokenSafetyScore(0x3B8A6D696f2104A9aC617bB91e6811f489498047);

// Check before swap
require(oracle.isSafe(tokenAddress, 60), "Token safety score too low");
```

### API

```bash
curl "https://cryptogenesis.duckdns.org/token/scan?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base"
```

```json
{
  "safety_score": 90,
  "verdict": "SAFE",
  "flags": ["OWNERSHIP_NOT_RENOUNCED"],
  "scan_time_ms": 850
}
```

### MCP (for AI agents)

Connect to `https://cryptogenesis.duckdns.org/mcp/sse` and call the `check_token_safety` tool.

## License

MIT — The standard is open. Build on it.
