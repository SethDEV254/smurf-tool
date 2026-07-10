import type { StaticReport } from './types.ts';
import type { SandboxResult } from './sandbox.ts';

export function renderStaticMarkdown(report: StaticReport): string {
  const lines: string[] = [];
  lines.push(`# binarykit static analysis: \`${report.target}\``);
  lines.push('');
  lines.push(`- Scanned at: ${report.scannedAt}`);
  lines.push(
    `- Format: ${report.fileType.format}${report.fileType.arch ? ` (${report.fileType.arch}, ${report.fileType.bitness ?? '?'}-bit, ${report.fileType.endianness ?? '?'})` : ''}`
  );
  if (report.fileType.interpreter) lines.push(`- Interpreter: \`${report.fileType.interpreter}\``);
  lines.push(`- Size: ${report.hashes.size} bytes`);
  lines.push(`- SHA256: \`${report.hashes.sha256}\``);
  lines.push(`- SHA1: \`${report.hashes.sha1}\``);
  lines.push(`- MD5: \`${report.hashes.md5}\``);
  lines.push('');

  lines.push(`## Entropy`);
  lines.push('');
  lines.push(`- Overall: ${report.entropy.overall} bits/byte`);
  lines.push(
    `- High-entropy chunks (>=7.5 bits/byte, ${report.entropy.chunkSize}B each): ${report.entropy.highEntropyChunks.length}`
  );
  lines.push(
    `- Likely packed/encrypted: ${report.entropy.likelyPacked ? 'YES -- most of the file is dense, common for packers/crypters' : 'no'}`
  );
  lines.push('');

  lines.push(`## Strings`);
  lines.push('');
  lines.push(`- Total extracted: ${report.stringCount}`);
  if (report.flaggedStrings.suspiciousApis.length > 0) {
    lines.push(`- Suspicious API references: ${report.flaggedStrings.suspiciousApis.join(', ')}`);
  }
  if (report.flaggedStrings.urls.length > 0) {
    lines.push(`- URLs: ${report.flaggedStrings.urls.slice(0, 20).join(', ')}`);
  }
  if (report.flaggedStrings.ips.length > 0) {
    lines.push(`- IP addresses: ${report.flaggedStrings.ips.slice(0, 20).join(', ')}`);
  }
  if (report.flaggedStrings.licensingHints.length > 0) {
    lines.push(`- Licensing-related strings (${report.flaggedStrings.licensingHints.length}):`);
    for (const hint of report.flaggedStrings.licensingHints.slice(0, 15)) {
      lines.push(`  - \`${hint}\``);
    }
  }
  lines.push('');

  lines.push(`## Symbols`);
  lines.push('');
  if (!report.symbolsAvailable) {
    lines.push('`nm` not available or produced no dynamic symbol table.');
  } else {
    lines.push('Dynamic (exported) symbols and undefined (imported) symbols were captured separately --');
    lines.push('see the JSON report for the full `nm` output.');
  }

  return lines.join('\n');
}

export function renderSandboxMarkdown(target: string, result: SandboxResult): string {
  const lines: string[] = [];
  lines.push(`# binarykit sandbox run: \`${target}\``);
  lines.push('');
  lines.push(`- Sandboxed: ${result.sandboxed ? 'yes (bubblewrap)' : 'NO'}`);
  lines.push(`- Syscall log captured: ${result.stracedLog ? 'yes (strace)' : 'no (strace not installed)'}`);
  lines.push(`- Exit code: ${result.exitCode ?? '(killed on timeout)'}`);
  lines.push(`- Timed out: ${result.timedOut ? 'yes' : 'no'}`);
  lines.push(`- stdout: \`${result.stdoutPath}\``);
  lines.push(`- stderr: \`${result.stderrPath}\``);
  if (result.straceLogPath) lines.push(`- Full syscall log: \`${result.straceLogPath}\``);
  lines.push('');

  if (result.behavior) {
    lines.push(`## Behavior summary`);
    lines.push('');
    lines.push(`### Files touched (${result.behavior.filesTouched.length})`);
    for (const f of result.behavior.filesTouched.slice(0, 40)) lines.push(`- \`${f}\``);
    lines.push('');
    lines.push(`### Network attempts (${result.behavior.networkAttempts.length})`);
    for (const n of result.behavior.networkAttempts) lines.push(`- \`${n}\``);
    lines.push('');
    lines.push(`### Processes spawned (${result.behavior.processesSpawned.length})`);
    for (const p of result.behavior.processesSpawned) lines.push(`- \`${p}\``);
    lines.push('');
    lines.push(`### Top syscalls`);
    for (const [name, count] of result.behavior.topSyscalls) lines.push(`- ${name}: ${count}`);
  }

  return lines.join('\n');
}
