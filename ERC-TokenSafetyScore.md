---
eip: XXXX
title: Token Safety Score Standard
description: A standard interface for querying and publishing token safety scores on EVM chains
author: CryptoGen Security <Cryptogen@zohomail.eu>
status: Draft
type: Standards Track
category: ERC
created: 2026-04-04
---

## Abstract

This ERC defines a standard interface for token safety scoring — enabling smart contracts, wallets, DEX frontends, and AI agents to query whether an ERC-20 token is safe to interact with. It standardizes the scoring methodology, the on-chain interface for safety oracles, and the metadata format for off-chain safety reports.

## Motivation

The proliferation of scam tokens (honeypots, rug pulls, hidden mints, fee manipulation) causes billions in losses annually. Currently:

1. **No standard exists** for representing token safety — each tool uses proprietary scoring
2. **AI agents trading autonomously** have no standardized way to check token safety before executing trades
3. **DEX frontends and wallets** implement ad-hoc safety warnings with inconsistent methodologies
4. **Smart contracts cannot query safety data on-chain** — all safety tools are off-chain only

A standardized Token Safety Score enables:
- Any smart contract to gate interactions based on safety scores
- AI agents to discover and query safety oracles via a common interface
- DEX frontends to display consistent safety warnings
- Composable safety checks across the EVM ecosystem

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Safety Score

A Token Safety Score MUST be an unsigned integer from 0 to 100 where:
- **0-20**: DANGEROUS — High probability of scam/rug
- **21-40**: RISKY — Multiple warning signs detected
- **41-60**: CAUTION — Some concerns, proceed with care
- **61-80**: MODERATE — Minor issues detected
- **81-100**: SAFE — No significant issues found

### Interface

Every compliant Token Safety Oracle MUST implement the following interface:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC_TokenSafetyScore {
    /// @notice Emitted when a token's safety score is updated
    /// @param token The ERC-20 token address
    /// @param score The safety score (0-100)
    /// @param flags Bitmask of detected risk flags
    /// @param updatedAt Timestamp of the update
    event SafetyScoreUpdated(
        address indexed token,
        uint8 score,
        uint256 flags,
        uint256 updatedAt
    );

    /// @notice Get the safety score for a token
    /// @param token The ERC-20 token address
    /// @return score The safety score (0-100), or 0 if not scored
    /// @return flags Bitmask of detected risk flags
    /// @return updatedAt Timestamp of last update, or 0 if never scored
    function getSafetyScore(address token) 
        external view returns (uint8 score, uint256 flags, uint256 updatedAt);

    /// @notice Check if a token meets a minimum safety threshold
    /// @param token The ERC-20 token address
    /// @param minScore Minimum acceptable safety score
    /// @return safe Whether the token meets the threshold
    function isSafe(address token, uint8 minScore) 
        external view returns (bool safe);

    /// @notice Get the oracle's supported chain ID
    /// @return chainId The EVM chain ID this oracle covers
    function chainId() external view returns (uint256);

    /// @notice Get the oracle operator/authority
    /// @return operator The address authorized to update scores
    function operator() external view returns (address);
}
```

### Risk Flags Bitmask

The `flags` field is a 256-bit bitmask where each bit represents a specific risk:

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | `UNVERIFIED` | Source code not verified |
| 1 | `HONEYPOT` | Sell transactions blocked or heavily taxed |
| 2 | `HIDDEN_MINT` | Owner can mint unlimited tokens |
| 3 | `BLACKLIST` | Owner can blacklist addresses |
| 4 | `FEE_MANIPULATION` | Owner can change fees to 100% |
| 5 | `TRADING_PAUSE` | Owner can disable trading |
| 6 | `PROXY_UPGRADEABLE` | Contract can be upgraded by owner |
| 7 | `SELF_DESTRUCT` | Contract contains selfdestruct |
| 8 | `DELEGATECALL` | Contract uses delegatecall |
| 9 | `OWNERSHIP_NOT_RENOUNCED` | Owner has privileged functions |
| 10 | `LOW_LIQUIDITY` | Less than $10K in DEX liquidity |
| 11 | `LP_NOT_LOCKED` | Liquidity provider tokens not locked |
| 12 | `HIGH_TAX` | Buy/sell tax exceeds 10% |
| 13 | `MAX_WALLET_LIMIT` | Owner can limit wallet holdings |
| 14 | `COOLDOWN_RESTRICTION` | Transfer cooldown restrictions |
| 15 | `EXTERNAL_CALL_RISK` | Sends ETH to external addresses |
| 16-255 | Reserved | For future risk categories |

### Off-Chain Metadata (OPTIONAL)

Oracles MAY provide extended metadata via an off-chain URI:

```solidity
interface IERC_TokenSafetyScoreMetadata {
    /// @notice Get URI for detailed safety report
    /// @param token The ERC-20 token address
    /// @return uri URI pointing to a JSON safety report
    function safetyReportURI(address token) 
        external view returns (string memory uri);
}
```

The JSON report at the URI SHOULD follow this schema:

```json
{
    "token": "0x...",
    "chain": "eip155:8453",
    "score": 85,
    "verdict": "SAFE",
    "flags": ["OWNERSHIP_NOT_RENOUNCED"],
    "analysis": {
        "verified": true,
        "honeypot": false,
        "owner_renounced": false,
        "proxy": false,
        "source_findings": [],
        "lp_locked": true,
        "holder_count": 1500
    },
    "scanner": "SafeAgent v2.0",
    "timestamp": 1712246400,
    "signature": "0x..."
}
```

### Discovery for AI Agents

Compliant oracles SHOULD expose a `.well-known/token-safety-oracle.json` endpoint:

```json
{
    "name": "SafeAgent Oracle",
    "version": "1.0.0",
    "chains": [8453, 1, 42161, 10, 137, 56],
    "contract": "0x...",
    "api": "https://api.safeagent.xyz/v1/score",
    "mcp": "https://mcp.safeagent.xyz/sse",
    "standard": "ERC-XXXX"
}
```

## Rationale

### Why 0-100 Score?

A continuous score (vs binary safe/unsafe) enables consumers to set their own risk tolerance. A DEX might require score > 60, while an AI agent trading memecoins might accept score > 30.

### Why On-Chain?

On-chain scores enable:
1. Smart contracts to gate token interactions (e.g., a DEX that refuses to list tokens with score < 40)
2. Composability — other protocols can read safety scores without off-chain dependencies
3. Transparency — all score updates are auditable on-chain

### Why Bitmask Flags?

Individual flags allow consumers to filter on specific risks. A stablecoin protocol might only care about `HONEYPOT` and `HIDDEN_MINT`, while a wallet might display all flags.

### Why Off-Chain Metadata?

Detailed analysis (source code findings, simulation results) is too large for on-chain storage. The URI pattern follows ERC-721's `tokenURI` convention.

## Backwards Compatibility

This ERC introduces a new interface and does not conflict with existing standards. Tokens do not need to implement this interface — the safety oracle is a separate contract that scores any ERC-20 token.

## Reference Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IERC_TokenSafetyScore.sol";

contract TokenSafetyOracle is IERC_TokenSafetyScore {
    address public override operator;
    uint256 public override chainId;
    
    struct Score {
        uint8 score;
        uint256 flags;
        uint256 updatedAt;
    }
    
    mapping(address => Score) private _scores;
    
    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }
    
    constructor(uint256 _chainId) {
        operator = msg.sender;
        chainId = _chainId;
    }
    
    function updateScore(address token, uint8 score, uint256 flags) 
        external onlyOperator 
    {
        require(score <= 100, "score > 100");
        _scores[token] = Score(score, flags, block.timestamp);
        emit SafetyScoreUpdated(token, score, flags, block.timestamp);
    }
    
    function batchUpdateScores(
        address[] calldata tokens, 
        uint8[] calldata scores, 
        uint256[] calldata flags
    ) external onlyOperator {
        require(tokens.length == scores.length && scores.length == flags.length, "length mismatch");
        for (uint i = 0; i < tokens.length; i++) {
            require(scores[i] <= 100, "score > 100");
            _scores[tokens[i]] = Score(scores[i], flags[i], block.timestamp);
            emit SafetyScoreUpdated(tokens[i], scores[i], flags[i], block.timestamp);
        }
    }
    
    function getSafetyScore(address token) 
        external view override 
        returns (uint8 score, uint256 flags, uint256 updatedAt) 
    {
        Score memory s = _scores[token];
        return (s.score, s.flags, s.updatedAt);
    }
    
    function isSafe(address token, uint8 minScore) 
        external view override 
        returns (bool safe) 
    {
        return _scores[token].score >= minScore && _scores[token].updatedAt > 0;
    }
    
    function transferOperator(address newOperator) external onlyOperator {
        operator = newOperator;
    }
}
```

## Security Considerations

1. **Oracle Trust**: Consumers must trust the oracle operator to provide accurate scores. Decentralized scoring (multiple oracles with aggregation) is RECOMMENDED for production use.

2. **Stale Scores**: Consumers SHOULD check `updatedAt` and define a maximum staleness threshold. A token scored 6 months ago may have changed.

3. **Score Manipulation**: Oracle operators could be bribed to provide false scores. Multi-oracle aggregation and reputation systems mitigate this risk.

4. **Front-Running**: Score updates are public transactions. Malicious actors could front-run score downgrades to exit positions. Private mempools or commit-reveal schemes can mitigate this.

5. **Gas Costs**: On-chain queries are view functions with minimal gas. Batch updates amortize gas costs across multiple tokens.

## Copyright

Copyright and related rights waived via CC0.
