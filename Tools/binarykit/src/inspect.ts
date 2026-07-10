import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { detectFileType } from './filetype.ts';
import { hashFile } from './hash.ts';
import { analyzeEntropy } from './entropy.ts';
import { extractStrings, flagStrings } from './strings.ts';
import { listSymbols } from './binutils.ts';
import type { StaticReport } from './types.ts';

export async function runStaticInspect(target: string): Promise<StaticReport> {
  const file = Bun.file(target);
  if (!(await file.exists())) throw new Error(`file not found: ${target}`);

  const buf = new Uint8Array(await file.arrayBuffer());
  const fileType = detectFileType(buf);
  const hashes = hashFile(buf);
  const entropy = analyzeEntropy(buf);
  const strings = extractStrings(buf);
  const flaggedStrings = flagStrings(strings);
  const symbols = await listSymbols(target);

  return {
    target,
    scannedAt: new Date().toISOString(),
    fileType,
    hashes,
    entropy,
    stringCount: strings.length,
    flaggedStrings,
    symbolsAvailable: symbols.dynamicSymbols !== null,
    dynamicSymbols: symbols.dynamicSymbols,
    undefinedSymbols: symbols.undefinedSymbols,
  };
}

export function writeReport(report: StaticReport, outPath: string): void {
  mkdirSync(dirname(outPath), { recursive: true });
  Bun.write(outPath, JSON.stringify(report, null, 2));
}

export function defaultReportPath(target: string): string {
  const safe = target.replace(/[\\/:]/g, '_');
  return join('reports', `${safe}-${Date.now()}.json`);
}
