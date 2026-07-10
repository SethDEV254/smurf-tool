import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export interface SandboxOptions {
  filePath: string;
  args?: string[];
  timeoutSeconds?: number;
  allowNetwork?: boolean;
  outDir?: string;
}

export interface SandboxBehaviorSummary {
  filesTouched: string[];
  networkAttempts: string[];
  processesSpawned: string[];
  topSyscalls: [string, number][];
}

export interface SandboxResult {
  exitCode: number | null;
  timedOut: boolean;
  sandboxed: boolean;
  stracedLog: boolean;
  stdoutPath: string;
  stderrPath: string;
  straceLogPath: string | null;
  behavior: SandboxBehaviorSummary | null;
}

function isAvailable(tool: string): boolean {
  return Bun.which(tool) !== null;
}

export function parseStraceLog(text: string): SandboxBehaviorSummary {
  const files = new Set<string>();
  const network = new Set<string>();
  const processes = new Set<string>();
  const syscallCounts = new Map<string, number>();

  const lineRe = /^(?:\[pid\s+\d+\]\s+|\d+\s+)?\d{2}:\d{2}:\d{2}\.\d+\s+(\w+)\((.*)$/;

  for (const line of text.split('\n')) {
    const m = line.match(lineRe);
    if (!m) continue;
    const [, syscall, rest] = m;
    syscallCounts.set(syscall, (syscallCounts.get(syscall) ?? 0) + 1);

    if (syscall === 'openat' || syscall === 'open') {
      const pathMatch = rest.match(/"((?:[^"\\]|\\.)*)"/);
      if (pathMatch) files.add(pathMatch[1]);
    } else if (syscall === 'execve') {
      const pathMatch = rest.match(/"((?:[^"\\]|\\.)*)"/);
      if (pathMatch) processes.add(pathMatch[1]);
    } else if (syscall === 'connect' || syscall === 'sendto') {
      const addrMatch = rest.match(/inet_addr\("([^"]+)"\)/) ?? rest.match(/sin_addr=inet_addr\("([^"]+)"\)/);
      const portMatch = rest.match(/sin_port=htons\((\d+)\)/);
      if (addrMatch) network.add(portMatch ? `${addrMatch[1]}:${portMatch[1]}` : addrMatch[1]);
    }
  }

  const topSyscalls = [...syscallCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);

  return {
    filesTouched: [...files].slice(0, 200),
    networkAttempts: [...network],
    processesSpawned: [...processes],
    topSyscalls,
  };
}

/**
 * Runs `filePath` inside a bubblewrap sandbox (unshared namespaces, read-only root,
 * tmpfs scratch, no network unless `allowNetwork`) with strace attached, then parses
 * the syscall log into a behavior summary. Refuses to run unsandboxed -- if bwrap
 * isn't installed, this throws rather than executing the target directly.
 */
export async function runSandboxed(opts: SandboxOptions): Promise<SandboxResult> {
  if (!isAvailable('bwrap')) {
    throw new Error(
      "bubblewrap ('bwrap') is not installed -- refusing to run the target unsandboxed. " +
        'Install it (see scripts/install-linux.sh) before using `binarykit sandbox`.'
    );
  }
  const straced = isAvailable('strace');

  const outDir = opts.outDir ?? 'reports';
  mkdirSync(outDir, { recursive: true });
  const base = `${opts.filePath.replace(/[\\/:]/g, '_')}-${Date.now()}`;
  const stdoutPath = join(outDir, `${base}.stdout.log`);
  const stderrPath = join(outDir, `${base}.stderr.log`);
  // bwrap's --tmpfs /tmp is private to the sandbox's mount namespace and vanishes
  // when the process exits, so anything written there (e.g. the strace log) would
  // be unreadable from the host afterward. Bind a host-writable scratch dir at
  // /tmp instead, so both the target's own /tmp usage and the strace log persist.
  const scratchDir = resolve(join(outDir, `${base}.tmp`));
  mkdirSync(scratchDir, { recursive: true });
  const straceLogPath = straced ? join(scratchDir, 'strace.log') : null;

  const absTarget = resolve(opts.filePath);
  const timeoutSeconds = opts.timeoutSeconds ?? 15;

  const bwrapArgs = [
    '--die-with-parent',
    '--unshare-pid',
    '--unshare-uts',
    '--unshare-ipc',
    '--unshare-cgroup-try',
    ...(opts.allowNetwork ? [] : ['--unshare-net']),
    '--ro-bind',
    '/',
    '/',
    '--dev',
    '/dev',
    '--proc',
    '/proc',
    '--bind',
    scratchDir,
    '/tmp',
    '--chdir',
    '/tmp',
    '--',
  ];

  const innerCommand = straced
    ? ['strace', '-f', '-tt', '-o', '/tmp/strace.log', absTarget, ...(opts.args ?? [])]
    : [absTarget, ...(opts.args ?? [])];

  const fullArgs = ['bwrap', ...bwrapArgs, ...innerCommand];

  const proc = Bun.spawn(fullArgs, { stdout: 'pipe', stderr: 'pipe' });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill();
  }, timeoutSeconds * 1000);

  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  clearTimeout(timer);

  mkdirSync(dirname(stdoutPath), { recursive: true });
  await Bun.write(stdoutPath, stdout);
  await Bun.write(stderrPath, stderr);

  let behavior: SandboxBehaviorSummary | null = null;
  if (straceLogPath) {
    try {
      behavior = parseStraceLog(readFileSync(straceLogPath, 'utf8'));
    } catch {
      behavior = null;
    }
  }

  return {
    exitCode: timedOut ? null : exitCode,
    timedOut,
    sandboxed: true,
    stracedLog: straced,
    stdoutPath,
    stderrPath,
    straceLogPath,
    behavior,
  };
}
