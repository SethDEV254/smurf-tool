import type { Finding, Severity } from './types.ts';

function mapImpact(impact: string): Severity {
  switch ((impact ?? '').toLowerCase()) {
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'informational';
  }
}

/** Returns null if slither isn't installed, [] if it ran but found nothing, else its findings. */
export async function runSlither(targetPath: string): Promise<Finding[] | null> {
  const bin = Bun.which('slither');
  if (!bin) return null;

  const proc = Bun.spawn([bin, targetPath, '--json', '-'], {
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  if (!stdout.trim()) return [];

  let parsed: any;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }

  const results = parsed?.results?.detectors ?? [];
  const findings: Finding[] = [];
  for (const r of results) {
    const el = r.elements?.[0];
    const mapping = el?.source_mapping;
    const file = mapping?.filename_relative ?? targetPath;
    const line = mapping?.lines?.[0] ?? 0;
    findings.push({
      id: `slither:${r.check}:${file}:${line}`,
      detector: `slither:${r.check}`,
      severity: mapImpact(r.impact),
      title: r.check,
      description: (r.description ?? r.check).trim(),
      file,
      line,
      contract: el?.type === 'contract' ? el.name : undefined,
      function: el?.type === 'function' ? el.name : undefined,
    });
  }
  return findings;
}
