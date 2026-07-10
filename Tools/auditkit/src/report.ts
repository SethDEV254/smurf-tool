import type { Finding, ScanReport, Severity } from './types.ts';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '[CRIT]',
  high: '[HIGH]',
  medium: '[MED] ',
  low: '[LOW] ',
  informational: '[INFO]',
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (sev !== 0) return sev;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });
}

export function renderMarkdown(report: ScanReport): string {
  const findings = sortFindings(report.findings);
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  for (const f of findings) counts[f.severity]++;

  const lines: string[] = [];
  lines.push(`# auditkit static scan report`);
  lines.push('');
  lines.push(`- Target: \`${report.target}\``);
  lines.push(`- Scanned at: ${report.scannedAt}`);
  lines.push(`- Detectors run: ${report.detectorsRun.join(', ')}`);
  lines.push(`- slither: ${report.slitherAvailable ? 'available, included' : 'not found on PATH, skipped'}`);
  lines.push('');
  lines.push(
    `Summary: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ` +
      `${counts.low} low, ${counts.informational} informational`
  );
  lines.push('');

  if (findings.length === 0) {
    lines.push('No findings.');
    return lines.join('\n');
  }

  for (const f of findings) {
    lines.push(`## ${SEVERITY_EMOJI[f.severity]} ${f.title}`);
    lines.push('');
    lines.push(`- Severity: **${f.severity}**`);
    lines.push(`- Detector: \`${f.detector}\``);
    lines.push(`- Location: \`${f.file}:${f.line}\`${f.function ? ` in \`${f.function}\`` : ''}`);
    if (f.exploitTemplate) {
      lines.push(`- Exploit template available: \`${f.exploitTemplate}\``);
    }
    lines.push(`- Finding ID: \`${f.id}\``);
    lines.push('');
    lines.push(f.description);
    lines.push('');
  }

  return lines.join('\n');
}
