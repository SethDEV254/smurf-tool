import parser from '@solidity-parser/parser';
import type { Detector, Finding } from '../types.ts';
import { contractsOf, functionsOf, lineOf } from '../ast.ts';
import { flattenStatements, unwrapCallExpression } from './shared.ts';

/** Flags low-level `.call(...)` sites whose success return value is discarded or never require()'d nearby. */
export const uncheckedCallDetector: Detector = ({ filePath, ast }) => {
  const findings: Finding[] = [];

  for (const contract of contractsOf(ast)) {
    for (const fn of functionsOf(contract)) {
      if (!fn.body) continue;
      const statements = flattenStatements(fn.body);

      for (let i = 0; i < statements.length; i++) {
        const stmt = statements[i];
        let callNode: any = null;
        parser.visit(stmt, {
          FunctionCall(n: any) {
            const expr = unwrapCallExpression(n.expression);
            if (!callNode && expr?.type === 'MemberAccess' && expr.memberName === 'call') {
              callNode = n;
            }
          },
        });
        if (!callNode) continue;

        const line = lineOf(callNode);
        const isBareExpressionStmt =
          stmt.type === 'ExpressionStatement' && stmt.expression === callNode;

        if (isBareExpressionStmt) {
          findings.push({
            id: `unchecked-call:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'unchecked-call',
            severity: 'high',
            title: `Unchecked low-level call in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description:
              `The return value of '.call(...)' on line ${line} is fully discarded. If the call ` +
              `fails, execution continues as if it succeeded. Wrap in 'require(success, ...)' or ` +
              `an explicit check.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
          });
          continue;
        }

        let declaredNames: string[] = [];
        if (stmt.type === 'VariableDeclarationStatement') {
          declaredNames = (stmt.variables ?? [])
            .filter(Boolean)
            .map((v: any) => v.name)
            .filter(Boolean);
        }
        if (declaredNames.length === 0) continue;

        const checked = statements.slice(i + 1, i + 6).some((later) => {
          let hit = false;
          parser.visit(later, {
            FunctionCall(n: any) {
              if (n.expression?.type === 'Identifier' && n.expression.name === 'require') {
                const argSrc = JSON.stringify(n.arguments ?? []);
                if (declaredNames.some((name) => argSrc.includes(`"name":"${name}"`))) hit = true;
              }
            },
          });
          return hit;
        });

        if (!checked) {
          findings.push({
            id: `unchecked-call-soft:${contract.name}:${fn.name ?? '<fallback>'}:${line}`,
            detector: 'unchecked-call',
            severity: 'medium',
            title: `Call success not obviously validated in ${contract.name}.${fn.name ?? '<fallback>'}`,
            description:
              `'.call(...)' on line ${line} captures a return value (${declaredNames.join(', ')}) but ` +
              `no 'require(...)' referencing it was found in the next few statements. Confirm the ` +
              `success flag is actually checked somewhere.`,
            file: filePath,
            line,
            contract: contract.name,
            function: fn.name ?? '<fallback>',
          });
        }
      }
    }
  }

  return findings;
};
