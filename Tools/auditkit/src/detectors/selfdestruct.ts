import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf } from '../ast.ts';
import { hasSenderCheckModifierOrGuard } from './shared.ts';

/** Flags `selfdestruct`/`suicide` reachable without an access-control modifier or require guard. */
export const selfdestructDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      const guarded = hasSenderCheckModifierOrGuard(fn);

      parser.visit(fn.body, {
        FunctionCall(n: any) {
          const name = n.expression?.name;
          if (name !== 'selfdestruct' && name !== 'suicide') return;
          const line = n.loc?.start?.line ?? 0;
          findings.push({
            id: `selfdestruct:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'selfdestruct',
            severity: guarded ? 'medium' : 'critical',
            title: `${guarded ? 'Guarded' : 'Unprotected'} selfdestruct in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description: guarded
              ? `'${name}(...)' on line ${line} appears to have an access-control modifier or ` +
                `require() guard. Double-check the guard actually restricts to trusted callers.`
              : `'${name}(...)' on line ${line} has no visible access-control modifier or require() ` +
                `guard, so any caller can permanently destroy this contract and force-send its ETH ` +
                `balance to an attacker-chosen address.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
            exploitTemplate: guarded ? undefined : 'access-control-hijack',
          });
        },
      });
    }
  }

  return findings;
};
