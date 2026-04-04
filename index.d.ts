export interface SafetyReport {
  address: string;
  chain: string;
  token: { name: string; symbol: string; decimals: number };
  safety_score: number;
  verdict: string;
  flags: string[];
  scan_time_ms: number;
  timestamp: number;
}

export function checkTokenSafety(address: string, chain?: string): Promise<SafetyReport>;
export function deepScan(address: string, chain?: string): Promise<SafetyReport>;
export function isSafe(address: string, chain?: string, minScore?: number): Promise<boolean>;
export function decodeFlags(flagsBitmask: number): string[];

export const FLAGS: Record<string, number>;
export const CHAINS: string[];
export const ORACLE_ADDRESS: string;
export const ORACLE_ABI: string[];
export const MCP_SSE: string;
export const API_BASE: string;
