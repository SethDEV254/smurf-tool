import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf } from '../ast.ts';

const WEAK_ENTROPY_MEMBERS: Record<string, string> = {
  timestamp: 'block.timestamp',
  difficulty: 'block.difficulty',
  prevrandao: 'block.prevrandao',
  number: 'block.number',
};

/** Flags on-chain "randomness" derived from miner/validator-influenceable or predictable values. */
export const weakRandomnessDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      parser.visit(fn.body, {
        MemberAccess(n: any) {
          if (n.expression?.type === 'Identifier' && n.expression.name === 'block') {
            const label = WEAK_ENTROPY_MEMBERS[n.memberName];
            if (!label) return;
            const line = n.loc?.start?.line ?? 0;
            findings.push({
              id: `weak-randomness:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
              detector: 'weak-randomness',
              severity: 'medium',
              title: `Weak entropy source (${label}) in ${contract.name}.${fn.name ?? '<fallback>'}`,
              description:
                `'${label}' on line ${line} is visible on-chain before the transaction is mined and, ` +
                `for timestamp/difficulty/prevrandao, is influenceable by the block producer. Do not ` +
                `use it (alone or hashed) as a source of randomness for anything of value -- use ` +
                `Chainlink VRF or a commit-reveal scheme instead.`,
              file: filePath,
              line,
              contract: contract.name,
              function: fn.name ?? '<fallback>',
            });
          }
        },
        FunctionCall(n: any) {
          if (n.expression?.name === 'blockhash') {
            const line = n.loc?.start?.line ?? 0;
            findings.push({
              id: `weak-randomness-blockhash:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
              detector: 'weak-randomness',
              severity: 'medium',
              title: `blockhash() used as entropy in ${contract.name}.${fn.name ?? '<fallback>'}`,
              description:
                `'blockhash(...)' on line ${line} is predictable/manipulable and only retains the ` +
                `last 256 blocks. Not suitable as a randomness source for anything of value.`,
              file: filePath,
              line,
              contract: contract.name,
              function: fn.name ?? '<fallback>',
            });
          }
        },
      });
    }
  }

  return findings;
};
