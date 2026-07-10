#!/usr/bin/env bun
import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { runStaticScan, writeReport, defaultFindingsPath } from './static.ts';
import { renderMarkdown } from './report.ts';
import { recon, CHAIN_IDS } from './recon.ts';
import { generateFuzzTest } from './fuzz.ts';
import { generateExploit, listExploitTemplates } from './exploit/generate.ts';
import type { Finding, ScanReport } from './types.ts';

const program = new Command();

program
  .name('auditkit')
  .description(
    'Local smart contract auditing toolkit: static analysis, fuzz scaffolds, and exploit PoC ' +
      'generation against forked/local/testnet chains. Point exploit PoCs at contracts you own ' +
      'or are authorized to test -- they fork chain state locally via Anvil, no live funds are touched.'
  )
  .version('0.1.0');

program
  .command('recon')
  .description('Fetch verified source for a deployed contract from a block explorer (Etherscan v2 API).')
  .requiredOption('-a, --address <address>', 'contract address')
  .option('-c, --chain <name-or-id>', 'chain name (mainnet, sepolia, polygon, arbitrum, optimism, base, bsc, avalanche) or numeric chain id', 'mainnet')
  .option('-o, --out <dir>', 'output directory (default: contracts/<address>-chain<id>)')
  .action(async (opts) => {
    const chainId = CHAIN_IDS[opts.chain.toLowerCase()] ?? Number(opts.chain);
    if (!Number.isFinite(chainId)) {
      console.error(`unknown chain '${opts.chain}'. Known names: ${Object.keys(CHAIN_IDS).join(', ')}`);
      process.exit(1);
    }
    const apiKey = process.env.ETHERSCAN_API_KEY ?? '';
    try {
      const result = await recon({ address: opts.address, chainId, apiKey, outDir: opts.out });
      console.log(`fetched ${result.contractName} (solc ${result.compilerVersion}) -> ${result.outDir}`);
      for (const f of result.files) console.log(`  ${f}`);
    } catch (err) {
      console.error(`recon failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('static')
  .description('Run static detectors (custom AST heuristics + slither if installed) over a contract or directory.')
  .argument('<path>', 'path to a .sol file or a directory tree')
  .option('--no-slither', 'skip slither even if installed')
  .option('-o, --out <file>', 'findings JSON output path (default: findings/<target>-<timestamp>.json)')
  .option('-m, --md <file>', 'also write a Markdown report to this path')
  .action(async (path, opts) => {
    try {
      const report = await runStaticScan(path, { skipSlither: !opts.slither });
      const outPath = opts.out ?? defaultFindingsPath(path);
      writeReport(report, outPath);
      console.log(`wrote ${report.findings.length} findings -> ${outPath}`);
      if (opts.md) {
        await Bun.write(opts.md, renderMarkdown(report));
        console.log(`wrote report -> ${opts.md}`);
      }
      const bySeverity = report.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});
      console.log(JSON.stringify(bySeverity));
    } catch (err) {
      console.error(`static scan failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('fuzz')
  .description('Generate a Foundry fuzz-test scaffold for a contract\'s public/external functions.')
  .argument('<path>', 'path to a .sol file')
  .option('-c, --contract <name>', 'contract name (default: first contract in the file)')
  .option('-o, --out <dir>', 'output directory', 'test/fuzz')
  .action(async (path, opts) => {
    try {
      const result = await generateFuzzTest({ filePath: path, contractName: opts.contract, outDir: opts.out });
      console.log(`wrote ${result.outPath}`);
      console.log(`fuzzed: ${result.fuzzedFunctions.join(', ') || '(none)'}`);
      if (result.skippedFunctions.length > 0) {
        console.log(`skipped (non-elementary params, needs manual harness): ${result.skippedFunctions.join(', ')}`);
      }
    } catch (err) {
      console.error(`fuzz scaffold generation failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('exploit')
  .description('Generate a Foundry exploit PoC scaffold for a specific finding.')
  .requiredOption('-f, --findings <file>', 'findings JSON file produced by `auditkit static`')
  .requiredOption('-i, --id <findingId>', 'finding id to generate a PoC for')
  .option('-a, --address <address>', 'deployed address of the target contract (fills the PoC\'s target var)')
  .option('-o, --out <dir>', 'output directory', 'test/exploits')
  .action(async (opts) => {
    try {
      const raw: ScanReport = JSON.parse(readFileSync(opts.findings, 'utf8'));
      const finding = raw.findings.find((f: Finding) => f.id === opts.id);
      if (!finding) {
        console.error(`finding '${opts.id}' not found in ${opts.findings}`);
        process.exit(1);
      }
      if (!finding.exploitTemplate) {
        console.error(
          `finding '${opts.id}' (${finding.detector}) has no exploit template. Available templates: ` +
            listExploitTemplates().join(', ')
        );
        process.exit(1);
      }
      const result = await generateExploit({ finding, contractAddress: opts.address, outDir: opts.out });
      console.log(`wrote ${result.outPath} (template: ${result.template})`);
      console.log(
        `Fill in the TODOs, then: forge test --match-path ${result.outPath.split('\\').join('/')} -vvvv`
      );
    } catch (err) {
      console.error(`exploit generation failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Render a findings JSON file as Markdown.')
  .argument('<findingsFile>', 'findings JSON file produced by `auditkit static`')
  .option('-o, --out <file>', 'write Markdown to this path instead of stdout')
  .action(async (findingsFile, opts) => {
    const raw: ScanReport = JSON.parse(readFileSync(findingsFile, 'utf8'));
    const md = renderMarkdown(raw);
    if (opts.out) {
      await Bun.write(opts.out, md);
      console.log(`wrote ${opts.out}`);
    } else {
      console.log(md);
    }
  });

program.parseAsync(process.argv);
