import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', 'lib', 'out', 'cache', 'broadcast', '.git', 'artifacts']);

export function collectSolidityFiles(target: string): string[] {
  const st = statSync(target);
  if (st.isFile()) return target.endsWith('.sol') ? [target] : [];

  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(join(dir, entry.name));
      } else if (entry.isFile() && entry.name.endsWith('.sol')) {
        out.push(join(dir, entry.name));
      }
    }
  };
  walk(target);
  return out;
}
