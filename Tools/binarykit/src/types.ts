import type { FileTypeInfo } from './filetype.ts';
import type { FileHashes } from './hash.ts';
import type { EntropyReport } from './entropy.ts';
import type { FlaggedStrings } from './strings.ts';

export interface StaticReport {
  target: string;
  scannedAt: string;
  fileType: FileTypeInfo;
  hashes: FileHashes;
  entropy: EntropyReport;
  stringCount: number;
  flaggedStrings: FlaggedStrings;
  symbolsAvailable: boolean;
  dynamicSymbols: string | null;
  undefinedSymbols: string | null;
}
