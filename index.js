/**
 * SafeAgent SDK — Token safety checks for AI agents
 * 
 * @example
 * const { checkTokenSafety, isSafe } = require('safeagent-sdk');
 * 
 * // Check any token
 * const result = await checkTokenSafety('0x...', 'base');
 * console.log(result.safety_score); // 0-100
 * console.log(result.verdict);      // "SAFE" | "CAUTION" | "DANGEROUS"
 * 
 * // Quick boolean check
 * const safe = await isSafe('0x...', 'base', 60); // minimum score 60
 */

const API_BASE = 'https://cryptogenesis.duckdns.org/token';
const MCP_SSE = 'https://cryptogenesis.duckdns.org/mcp/sse';

// ERC Token Safety Score flag definitions
const FLAGS = {
  UNVERIFIED: 1 << 0,
  HONEYPOT: 1 << 1,
  HIDDEN_MINT: 1 << 2,
  BLACKLIST: 1 << 3,
  FEE_MANIPULATION: 1 << 4,
  TRADING_PAUSE: 1 << 5,
  PROXY_UPGRADEABLE: 1 << 6,
  SELF_DESTRUCT: 1 << 7,
  DELEGATECALL: 1 << 8,
  OWNERSHIP_NOT_RENOUNCED: 1 << 9,
  LOW_LIQUIDITY: 1 << 10,
  LP_NOT_LOCKED: 1 << 11,
  HIGH_TAX: 1 << 12,
  MAX_WALLET_LIMIT: 1 << 13,
};

const CHAINS = ['base', 'ethereum', 'arbitrum', 'optimism', 'polygon', 'bsc'];

// Optimism oracle contract
const ORACLE_ADDRESS = '0x3B8A6D696f2104A9aC617bB91e6811f489498047';
const ORACLE_ABI = [
  'function getSafetyScore(address token) view returns (uint8 score, uint256 flags, uint256 updatedAt)',
  'function isSafe(address token, uint8 minScore) view returns (bool safe)',
];

/**
 * Check token safety via API
 * @param {string} address - Token contract address
 * @param {string} chain - Chain name (base, ethereum, arbitrum, optimism, polygon, bsc)
 * @returns {Promise<Object>} Safety report with score, verdict, flags
 */
async function checkTokenSafety(address, chain = 'base') {
  if (!CHAINS.includes(chain)) {
    throw new Error(`Unsupported chain: ${chain}. Supported: ${CHAINS.join(', ')}`);
  }

  const response = await fetch(`${API_BASE}/scan?address=${address}&chain=${chain}`);
  if (!response.ok) {
    throw new Error(`Safety check failed: ${response.statusText}`);
  }
  return response.json();
}

/**
 * Deep safety scan with source code analysis
 * @param {string} address - Token contract address  
 * @param {string} chain - Chain name
 * @returns {Promise<Object>} Detailed safety report
 */
async function deepScan(address, chain = 'base') {
  const response = await fetch(`${API_BASE}/scan/deep?address=${address}&chain=${chain}`);
  if (!response.ok) {
    throw new Error(`Deep scan failed: ${response.statusText}`);
  }
  return response.json();
}

/**
 * Quick boolean safety check
 * @param {string} address - Token contract address
 * @param {string} chain - Chain name
 * @param {number} minScore - Minimum acceptable score (0-100)
 * @returns {Promise<boolean>} Whether the token meets the minimum score
 */
async function isSafe(address, chain = 'base', minScore = 60) {
  const result = await checkTokenSafety(address, chain);
  return result.safety_score >= minScore;
}

/**
 * Decode risk flags bitmask into human-readable array
 * @param {number} flagsBitmask - The flags bitmask from the safety score
 * @returns {string[]} Array of flag names
 */
function decodeFlags(flagsBitmask) {
  const activeFlags = [];
  for (const [name, bit] of Object.entries(FLAGS)) {
    if (flagsBitmask & bit) {
      activeFlags.push(name);
    }
  }
  return activeFlags;
}

module.exports = {
  checkTokenSafety,
  deepScan,
  isSafe,
  decodeFlags,
  FLAGS,
  CHAINS,
  ORACLE_ADDRESS,
  ORACLE_ABI,
  MCP_SSE,
  API_BASE,
};
