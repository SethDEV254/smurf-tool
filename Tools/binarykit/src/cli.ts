#!/usr/bin/env bun
import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { runStaticInspect, writeReport, defaultReportPath } from './inspect.ts';
import { renderStaticMarkdown, renderSandboxMarkdown } from './report.ts';
import { runSandboxed } from './sandbox.ts';
import { disassemble } from './binutils.ts';
import type { StaticReport } from './types.ts';

const program = new Command();

program
  .name('binarykit')
  .description(
    'Local reverse-engineering / binary-analysis toolkit: static analysis (hash, entropy, ' +
      'strings, symbols) and sandboxed dynamic analysis (isolated execution with syscall/network ' +
      'logging). For binaries you own or are authorized to analyze -- observability only, no ' +
      'patching, keygen, or protection-bypass generation.'
  )
  .version('0.1.0');

program
  .command('inspect')
  .description('Static analysis: file format, hashes, entropy (packing detection), strings, symbols.')
  .argument('<file>', 'path to the binary')
  .option('-o, --out <file>', 'JSON output path (default: reports/<name>-<timestamp>.json)')
  .option('-m, --md <file>', 'also write a Markdown report to this path')
  .action(async (file, opts) => {
    try {
      const report = await runStaticInspect(file);
      const outPath = opts.out ?? defaultReportPath(file);
      writeReport(report, outPath);
      console.log(`wrote ${outPath}`);
      console.log(
        `${report.fileType.format}${report.fileType.arch ? ` (${report.fileType.arch})` : ''}, ` +
          `${report.hashes.size} bytes, entropy ${report.entropy.overall}` +
          `${report.entropy.likelyPacked ? ' [LIKELY PACKED]' : ''}, ${report.stringCount} strings`
      );
      if (opts.md) {
        await Bun.write(opts.md, renderStaticMarkdown(report));
        console.log(`wrote report -> ${opts.md}`);
      }
    } catch (err) {
      console.error(`inspect failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('disasm')
  .description('Disassemble a binary (or one symbol) via objdump.')
  .argument('<file>', 'path to the binary')
  .option('-s, --symbol <name>', 'disassemble only this symbol')
  .option('-n, --max-lines <n>', 'truncate output after this many lines', '200')
  .action(async (file, opts) => {
    const out = await disassemble(file, { symbol: opts.symbol, maxLines: Number(opts.maxLines) });
    if (out === null) {
      console.error("objdump is not installed -- can't disassemble. See scripts/install-linux.sh.");
      process.exit(1);
    }
    console.log(out);
  });

program
  .command('sandbox')
  .description(
    'Run a binary inside an isolated bubblewrap sandbox with strace attached, capturing file/' +
      'network/process activity. No network access by default. Refuses to run unsandboxed.'
  )
  .argument('<file>', 'path to the binary')
  .option('-a, --args <args...>', 'arguments to pass to the target')
  .option('-t, --timeout <seconds>', 'kill the process after this many seconds', '15')
  .option('--allow-network', 'do not isolate the network namespace (default: isolated, no network)')
  .option('-o, --out <dir>', 'output directory for logs', 'reports')
  .option('-m, --md <file>', 'also write a Markdown behavior report to this path')
  .action(async (file, opts) => {
    try {
      const result = await runSandboxed({
        filePath: file,
        args: opts.args,
        timeoutSeconds: Number(opts.timeout),
        allowNetwork: Boolean(opts.allowNetwork),
        outDir: opts.out,
      });
      console.log(`exit code: ${result.exitCode ?? '(killed on timeout)'}`);
      console.log(`stdout: ${result.stdoutPath}`);
      console.log(`stderr: ${result.stderrPath}`);
      if (result.straceLogPath) console.log(`strace log: ${result.straceLogPath}`);
      if (result.behavior) {
        console.log(
          `files touched: ${result.behavior.filesTouched.length}, ` +
            `network attempts: ${result.behavior.networkAttempts.length}, ` +
            `processes spawned: ${result.behavior.processesSpawned.length}`
        );
      }
      if (opts.md) {
        await Bun.write(opts.md, renderSandboxMarkdown(file, result));
        console.log(`wrote report -> ${opts.md}`);
      }
    } catch (err) {
      console.error(`sandbox run failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Render a static-inspect JSON report as Markdown.')
  .argument('<reportFile>', 'JSON file produced by `binarykit inspect`')
  .option('-o, --out <file>', 'write Markdown to this path instead of stdout')
  .action(async (reportFile, opts) => {
    const raw: StaticReport = JSON.parse(readFileSync(reportFile, 'utf8'));
    const md = renderStaticMarkdown(raw);
    if (opts.out) {
      await Bun.write(opts.out, md);
      console.log(`wrote ${opts.out}`);
    } else {
      console.log(md);
    }
  });

program.parseAsync(process.argv);
