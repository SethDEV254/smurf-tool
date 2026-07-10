import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const CHAIN_IDS: Record<string, number> = {
  mainnet: 1,
  ethereum: 1,
  sepolia: 11155111,
  polygon: 137,
  arbitrum: 42161,
  optimism: 10,
  base: 8453,
  bsc: 56,
  avalanche: 43114,
};

export interface ReconOptions {
  address: string;
  chainId: number;
  apiKey: string;
  outDir?: string;
}

export interface ReconResult {
  contractName: string;
  compilerVersion: string;
  outDir: string;
  files: string[];
}

function safeParseAbi(abi: string): unknown {
  try {
    return JSON.parse(abi);
  } catch {
    return null;
  }
}

/** Fetches verified source for a deployed contract from the Etherscan v2 multichain API. */
export async function recon(opts: ReconOptions): Promise<ReconResult> {
  if (!opts.apiKey) {
    throw new Error('ETHERSCAN_API_KEY is not set (see .env.example)');
  }

  const url = new URL('https://api.etherscan.io/v2/api');
  url.searchParams.set('chainid', String(opts.chainId));
  url.searchParams.set('module', 'contract');
  url.searchParams.set('action', 'getsourcecode');
  url.searchParams.set('address', opts.address);
  url.searchParams.set('apikey', opts.apiKey);

  const res = await fetch(url);
  if (!res.ok) throw new Error(`etherscan request failed: HTTP ${res.status}`);
  const data: any = await res.json();

  if (data.status !== '1' || !Array.isArray(data.result) || data.result.length === 0) {
    throw new Error(`etherscan error: ${data.result ?? data.message ?? 'unknown error'}`);
  }

  const entry = data.result[0];
  if (!entry.SourceCode) {
    throw new Error(`contract ${opts.address} has no verified source on chain ${opts.chainId}`);
  }

  const outDir = opts.outDir ?? join('contracts', `${opts.address}-chain${opts.chainId}`);
  mkdirSync(outDir, { recursive: true });

  const files: string[] = [];
  let raw = entry.SourceCode as string;
  if (raw.startsWith('{{')) raw = raw.slice(1, -1);

  if (raw.trim().startsWith('{')) {
    let parsed: any = null;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = null;
    }
    const sources = parsed?.sources ?? parsed;
    if (sources && typeof sources === 'object') {
      for (const [relPath, val] of Object.entries<any>(sources)) {
        const content = typeof val === 'string' ? val : val?.content;
        if (typeof content !== 'string') continue;
        const safeRel = relPath.replace(/^[./]+/, '').replace(/\.\./g, '_');
        const dest = join(outDir, safeRel);
        mkdirSync(dirname(dest), { recursive: true });
        await Bun.write(dest, content);
        files.push(dest);
      }
    }
  }

  if (files.length === 0) {
    const dest = join(outDir, `${entry.ContractName || 'Contract'}.sol`);
    await Bun.write(dest, raw);
    files.push(dest);
  }

  await Bun.write(
    join(outDir, 'metadata.json'),
    JSON.stringify(
      {
        address: opts.address,
        chainId: opts.chainId,
        contractName: entry.ContractName,
        compilerVersion: entry.CompilerVersion,
        optimizationUsed: entry.OptimizationUsed,
        abi: safeParseAbi(entry.ABI),
      },
      null,
      2
    )
  );

  return {
    contractName: entry.ContractName || 'Unknown',
    compilerVersion: entry.CompilerVersion || 'unknown',
    outDir,
    files,
  };
}
