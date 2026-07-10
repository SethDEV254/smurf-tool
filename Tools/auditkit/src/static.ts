import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { detectors } from './detectors/index.ts';
import { parseSolidity } from './ast.ts';
import { runSlither } from './slither.ts';
import { collectSolidityFiles } from './fsutil.ts';
import type { Finding, ScanReport } from './types.ts';

export interface StaticScanOptions {
  skipSlither?: boolean;
}

export async function runStaticScan(target: string, opts: StaticScanOptions = {}): Promise<ScanReport> {
  const files = collectSolidityFiles(target);
  if (files.length === 0) throw new Error(`no .sol files found under ${target}`);

  const findings: Finding[] = [];
  const detectorNames = Object.keys(detectors);

  for (const file of files) {
    const source = await Bun.file(file).text();

    let ast: unknown;
    try {
      ast = parseSolidity(source, file);
    } catch (err) {
      findings.push({
        id: `parse-error:${file}`,
        detector: 'parser',
        severity: 'informational',
        title: `Could not parse ${file}`,
        description: (err as Error).message,
        file,
        line: 0,
      });
      continue;
    }

    for (const [name, detector] of Object.entries(detectors)) {
      try {
        findings.push(...detector({ filePath: file, source, ast }));
      } catch (err) {
        findings.push({
          id: `detector-error:${name}:${file}`,
          detector: name,
          severity: 'informational',
          title: `Detector '${name}' crashed on ${file}`,
          description: (err as Error).message,
          file,
          line: 0,
        });
      }
    }
  }

  let slitherAvailable = false;
  if (!opts.skipSlither) {
    const slitherFindings = await runSlither(target);
    if (slitherFindings !== null) {
      slitherAvailable = true;
      findings.push(...slitherFindings);
    }
  }

  return {
    target,
    scannedAt: new Date().toISOString(),
    findings,
    detectorsRun: detectorNames,
    slitherAvailable,
  };
}

export function writeReport(report: ScanReport, outPath: string): void {
  mkdirSync(dirname(outPath), { recursive: true });
  Bun.write(outPath, JSON.stringify(report, null, 2));
}

export function defaultFindingsPath(target: string): string {
  const safe = target.replace(/[\\/:]/g, '_');
  return join('findings', `${safe}-${Date.now()}.json`);
}
