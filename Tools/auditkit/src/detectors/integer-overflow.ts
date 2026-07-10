import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf, pragmaVersion, allowsPreCheckedArithmetic } from '../ast.ts';

const ARITH_OPS = new Set(['+', '-', '*', '+=', '-=', '*=', '++', '--']);

/** On pragma < 0.8.0 (no built-in overflow checks), flags raw arithmetic not wrapped by SafeMath. */
export const integerOverflowDetector: Detector = ({ filePath, ast, source }) => {
  const findings: Finding[] = [];
  const pragma = pragmaVersion(ast);
  if (!allowsPreCheckedArithmetic(pragma)) return findings;

  const usesSafeMath = /using\s+SafeMath\s+for/.test(source);

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      const seenLines = new Set<number>();
      parser.visit(fn.body, {
        BinaryOperation(n: any) {
          if (!ARITH_OPS.has(n.operator)) return;
          const line = n.loc?.start?.line ?? 0;
          if (seenLines.has(line)) return;
          seenLines.add(line);
          findings.push({
            id: `integer-overflow:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'integer-overflow',
            severity: usesSafeMath ? 'informational' : 'high',
            title: `Unchecked arithmetic (pragma ${pragma}) in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description: usesSafeMath
              ? `Arithmetic on line ${line} under pragma ${pragma}. Contract does 'using SafeMath', ` +
                `but confirm this specific operation actually uses a SafeMath method rather than a raw operator.`
              : `Arithmetic on line ${line} runs under pragma ${pragma}, which has no built-in ` +
                `over/underflow checks (added in 0.8.0), and no 'using SafeMath' was found. An overflow ` +
                `or underflow here silently wraps instead of reverting.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
            exploitTemplate: usesSafeMath ? undefined : 'integer-overflow-mint',
          });
        },
        UnaryOperation(n: any) {
          if (!ARITH_OPS.has(n.operator)) return;
          const line = n.loc?.start?.line ?? 0;
          if (seenLines.has(line)) return;
          seenLines.add(line);
          findings.push({
            id: `integer-overflow-unary:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'integer-overflow',
            severity: usesSafeMath ? 'informational' : 'medium',
            title: `Unchecked ${n.operator} (pragma ${pragma}) in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description:
              `'${n.operator}' on line ${line} runs under pragma ${pragma} with no overflow checks. ` +
              `Confirm the operand can never reach its type's bounds.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
          });
        },
      });
    }
  }

  return findings;
};
