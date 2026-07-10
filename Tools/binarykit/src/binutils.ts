export function isAvailable(tool: string): boolean {
  return Bun.which(tool) !== null;
}

async function runCapture(bin: string, args: string[]): Promise<string> {
  const proc = Bun.spawn([bin, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  return stdout;
}

export async function objdumpHeaders(filePath: string): Promise<string | null> {
  if (!isAvailable('objdump')) return null;
  return runCapture('objdump', ['-x', filePath]);
}

export interface SymbolInfo {
  dynamicSymbols: string | null;
  undefinedSymbols: string | null;
}

/** Defined vs. undefined dynamic symbols -- a rough proxy for exports vs. imports. */
export async function listSymbols(filePath: string): Promise<SymbolInfo> {
  if (!isAvailable('nm')) return { dynamicSymbols: null, undefinedSymbols: null };
  const [dynamicSymbols, undefinedSymbols] = await Promise.all([
    runCapture('nm', ['-D', '--defined-only', filePath]).catch(() => null),
    runCapture('nm', ['-D', '-u', filePath]).catch(() => null),
  ]);
  return { dynamicSymbols, undefinedSymbols };
}

export interface DisassembleOptions {
  symbol?: string;
  maxLines?: number;
}

/** Shells out to objdump -d. Returns null if objdump isn't installed. Output is truncated (default 200 lines) -- this is a triage excerpt, not a full disassembly dump. */
export async function disassemble(filePath: string, opts: DisassembleOptions = {}): Promise<string | null> {
  if (!isAvailable('objdump')) return null;
  const args = ['-d', '--no-show-raw-insn'];
  if (opts.symbol) args.push(`--disassemble=${opts.symbol}`);
  args.push(filePath);
  const out = await runCapture('objdump', args);
  const maxLines = opts.maxLines ?? 200;
  const lines = out.split('\n');
  if (lines.length <= maxLines) return out;
  return lines.slice(0, maxLines).join('\n') + `\n... (${lines.length - maxLines} more lines truncated)`;
}
