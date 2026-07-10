import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf } from '../ast.ts';

/** Flags `tx.origin` used for authentication -- phishable via a malicious intermediate contract. */
export const txOriginDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      parser.visit(fn.body, {
        MemberAccess(n: any) {
          if (n.expression?.type === 'Identifier' && n.expression.name === 'tx' && n.memberName === 'origin') {
            const line = n.loc?.start?.line ?? 0;
            findings.push({
              id: `tx-origin:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
              detector: 'tx-origin',
              severity: 'high',
              title: `tx.origin used in ${contract.name}.${fn.name ?? '<fallback>'}`,
              description:
                `'tx.origin' on line ${line} is unsafe for authorization: a victim tricked into ` +
                `calling an attacker's contract, which then calls this function, will still pass ` +
                `the check because tx.origin is the original EOA. Use 'msg.sender' instead.`,
              file: filePath,
              line,
              contract: contract.name,
              function: fn.name ?? '<fallback>',
              exploitTemplate: 'tx-origin-phishing',
            });
          }
        },
      });
    }
  }

  return findings;
};
