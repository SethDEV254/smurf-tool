import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf, lineOf } from '../ast.ts';

const INIT_NAME_RE = /^(initialize|init|setup|__init)/i;

/**
 * Flags upgradeable-style initializer functions that lack an `initializer`/`onlyInitializing`
 * modifier or an explicit re-init guard -- these can be called (or re-called) by anyone on an
 * implementation or unprotected proxy, hijacking ownership/config.
 */
export const unprotectedInitializerDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.name || !INIT_NAME_RE.test(fn.name)) continue;
      if (fn.visibility === 'private' || fn.visibility === 'internal') continue;

      const modifierNames = (fn.modifiers ?? []).map((m: any) => m.name);
      const hasOZGuardModifier = modifierNames.some((m: string) =>
        /initializer|onlyInitializing/i.test(m)
      );
      if (hasOZGuardModifier) continue;

      let hasManualGuard = false;
      if (fn.body) {
        parser.visit(fn.body, {
          FunctionCall(n: any) {
            if (n.expression?.type === 'Identifier' && n.expression.name === 'require') {
              const argSrc = JSON.stringify(n.arguments ?? []);
              if (/initialized/i.test(argSrc)) hasManualGuard = true;
            }
          },
        });
      }
      if (hasManualGuard) continue;

      findings.push({
        id: `unprotected-initializer:${contract.name}:${fn.name}:${lineOf(fn)}`,
        detector: 'unprotected-initializer',
        severity: 'critical',
        title: `Unprotected initializer ${contract.name}.${fn.name}`,
        description:
          `'${fn.name}(...)' looks like an upgradeable-pattern initializer but has no ` +
          `'initializer'/'onlyInitializing' modifier and no manual 'require(!initialized...)' guard. ` +
          `If deployed behind a proxy, anyone may be able to call (or re-call) it to seize ownership ` +
          `or overwrite configuration/storage.`,
        file: filePath,
        line: lineOf(fn),
        contract: contract.name,
        function: fn.name,
        exploitTemplate: 'access-control-hijack',
      });
    }
  }

  return findings;
};
