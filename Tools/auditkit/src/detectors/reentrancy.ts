import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf, stateVarNames, lineOf } from '../ast.ts';
import { flattenStatements, findExternalCalls, findStateVarWrites } from './shared.ts';

/**
 * Heuristic checks-effects-interactions violation detector: flags any state
 * write that occurs, in source order, after an external `.call`/`.delegatecall`
 * in the same function. Does not build a real CFG (no branch/loop fixpoint
 * analysis), so treat results as leads to verify, not proof.
 */
export const reentrancyDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    const stateVars = stateVarNames(contract);
    if (stateVars.size === 0) continue;

    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      const statements = flattenStatements(fn.body);

      let lastExternalCallLine: number | null = null;
      let lastExternalCallMember: string | null = null;

      for (const stmt of statements) {
        const calls = findExternalCalls(stmt);
        const writes = findStateVarWrites(stmt, stateVars);

        if (lastExternalCallLine !== null && writes.length > 0) {
          for (const w of writes) {
            findings.push({
              id: `reentrancy:${contract.name}:${fn.name ?? '<fallback>'}:${w.line}`,
              detector: 'reentrancy',
              severity: 'critical',
              title: `Possible reentrancy in ${contract.name}.${fn.name ?? '<fallback>'}`,
              description:
                `State variable '${w.name}' is written on line ${w.line}, after an external ` +
                `'.${lastExternalCallMember}(...)' call on line ${lastExternalCallLine} in the same ` +
                `function. If the call target is attacker-controlled, it can re-enter before this ` +
                `write lands (checks-effects-interactions violation). Verify a reentrancy guard ` +
                `or effects-before-interaction ordering is in place.`,
              file: filePath,
              line: w.line,
              contract: contract.name,
              function: fn.name ?? '<fallback>',
              exploitTemplate: 'reentrancy',
            });
          }
        }

        for (const c of calls) {
          if (!c.lowRisk) {
            lastExternalCallLine = c.line;
            lastExternalCallMember = c.member;
          }
        }
      }

      // Low-risk .send/.transfer note, once per function, informational only.
      const sendCalls = statements.flatMap((s) => findExternalCalls(s)).filter((c) => c.lowRisk);
      if (sendCalls.length > 0) {
        findings.push({
          id: `reentrancy-low-risk:${contract.name}:${fn.name ?? '<fallback>'}:${lineOf(fn)}`,
          detector: 'reentrancy',
          severity: 'informational',
          title: `.send/.transfer used in ${contract.name}.${fn.name ?? '<fallback>'}`,
          description:
            `Uses .send/.transfer (2300 gas stipend) instead of .call. Generally reentrancy-safe ` +
            `against state changes but can still break on gas-price changes or callees needing >2300 gas.`,
          file: filePath,
          line: sendCalls[0].line,
          contract: contract.name,
          function: fn.name ?? '<fallback>',
        });
      }
    }
  }

  return findings;
};
