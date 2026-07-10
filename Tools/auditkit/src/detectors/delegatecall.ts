import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf } from '../ast.ts';
import { unwrapCallExpression } from './shared.ts';

/**
 * Flags `.delegatecall(...)` where the target isn't an immutable/constant contract
 * reference -- delegatecall runs callee code in the caller's storage context, so an
 * attacker-controlled target can overwrite arbitrary storage slots (including owner/impl).
 */
export const delegatecallDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    const immutableOrConstantNames = new Set<string>();
    for (const sub of contract.subNodes ?? []) {
      if (sub.type === 'StateVariableDeclaration') {
        for (const v of sub.variables ?? []) {
          if (v?.isImmutable || v?.isDeclaredConst) immutableOrConstantNames.add(v.name);
        }
      }
    }

    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      parser.visit(fn.body, {
        FunctionCall(n: any) {
          const expr = unwrapCallExpression(n.expression);
          if (expr?.type !== 'MemberAccess' || expr.memberName !== 'delegatecall') return;
          const line = n.loc?.start?.line ?? 0;

          let targetName: string | null = null;
          let base = expr.expression;
          if (base?.type === 'FunctionCall' && base.expression?.name === 'address') {
            base = base.arguments?.[0];
          }
          if (base?.type === 'Identifier') targetName = base.name;

          const looksSafe = targetName !== null && immutableOrConstantNames.has(targetName);

          findings.push({
            id: `delegatecall:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'delegatecall',
            severity: looksSafe ? 'low' : 'critical',
            title: `delegatecall${looksSafe ? '' : ' to non-constant target'} in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description: looksSafe
              ? `'.delegatecall(...)' on line ${line} targets '${targetName}', which is declared ` +
                `immutable/constant. Lower risk, but still confirm it can never point at untrusted code.`
              : `'.delegatecall(...)' on line ${line} targets` +
                `${targetName ? ` '${targetName}'` : ' a dynamically computed address'}, which is not ` +
                `provably fixed. Delegatecall executes callee code with this contract's storage layout ` +
                `and msg.sender/msg.value -- an attacker-controlled target can overwrite arbitrary ` +
                `storage slots (e.g. owner, implementation slot) or drain funds. Restrict the target ` +
                `to a trusted, access-controlled address.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
            exploitTemplate: looksSafe ? undefined : 'delegatecall-storage-collision',
          });
        },
      });
    }
  }

  return findings;
};
