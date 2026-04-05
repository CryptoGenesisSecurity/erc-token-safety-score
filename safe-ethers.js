/**
 * SafeEthers — Drop-in ethers.js wrapper with SafeAgent Shield.
 *
 * Usage:
 *   const { SafeJsonRpcProvider, SafeWallet } = require('./safe-ethers');
 *   const provider = new SafeJsonRpcProvider("https://mainnet.base.org");
 *   const wallet = new SafeWallet(privateKey, provider);
 *   await wallet.sendTransaction(tx); // Checked automatically
 */

const { ethers } = require('ethers');

const SCANNER_URL = 'https://cryptogenesis.duckdns.org/token';
const MIN_SCORE = 40;
const APPROVE_SELECTOR = '0x095ea7b3';

async function checkSafety(address, chain = 'base') {
  try {
    const resp = await fetch(`${SCANNER_URL}/scan?address=${address}&chain=${chain}`);
    return await resp.json();
  } catch {
    return { safety_score: 100, verdict: 'UNKNOWN' }; // Failsafe
  }
}

class SafeWallet extends ethers.Wallet {
  constructor(privateKey, provider, options = {}) {
    super(privateKey, provider);
    this._chain = options.chain || 'base';
    this._minScore = options.minScore || MIN_SCORE;
    this._verbose = options.verbose !== false;
    this.shieldStats = { checked: 0, blocked: 0, allowed: 0 };
  }

  async sendTransaction(tx) {
    const to = tx.to?.toLowerCase();
    if (to) {
      this.shieldStats.checked++;

      const result = await checkSafety(to, this._chain);
      const score = result.safety_score ?? 100;

      if (score < this._minScore) {
        this.shieldStats.blocked++;
        const msg = `SafeAgent Shield: BLOCKED — ${to} scored ${score}/100 (${result.verdict})`;
        if (this._verbose) console.log(`🛡️ ${msg}`);
        throw new Error(msg);
      }

      // Check approve() calls
      if (tx.data?.startsWith(APPROVE_SELECTOR) && tx.data.length >= 74) {
        const spender = '0x' + tx.data.slice(34, 74);
        const spResult = await checkSafety(spender, this._chain);
        if ((spResult.safety_score ?? 100) < this._minScore) {
          this.shieldStats.blocked++;
          throw new Error(`SafeAgent Shield: BLOCKED approve — spender ${spender} scored ${spResult.safety_score}/100`);
        }
      }

      this.shieldStats.allowed++;
      if (this._verbose && score < 70) {
        console.log(`⚠️ SafeAgent: CAUTION — ${to} scored ${score}/100`);
      }
    }
    return super.sendTransaction(tx);
  }
}

function SafeJsonRpcProvider(url, chain = 'base') {
  const provider = new ethers.JsonRpcProvider(url);
  provider._chain = chain;
  return provider;
}

module.exports = { SafeWallet, SafeJsonRpcProvider, checkSafety };
