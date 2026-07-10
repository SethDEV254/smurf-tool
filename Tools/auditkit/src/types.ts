export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface Finding {
  id: string;
  detector: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  contract?: string;
  function?: string;
  exploitTemplate?: string;
}

export interface DetectorContext {
  filePath: string;
  source: string;
  ast: unknown;
}

export type Detector = (ctx: DetectorContext) => Finding[];

export interface ScanReport {
  target: string;
  scannedAt: string;
  findings: Finding[];
  detectorsRun: string[];
  slitherAvailable: boolean;
}
