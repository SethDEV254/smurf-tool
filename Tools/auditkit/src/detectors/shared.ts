import parser from '@solidity-parser/parser';

const ASSIGN_OPS = new Set(['=', '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=']);
const EXTERNAL_CALL_MEMBERS = new Set(['call', 'delegatecall', 'staticcall']);
const LOW_RISK_SEND_MEMBERS = new Set(['send', 'transfer']);

/** Flattens control-flow structure into a linear, in-source-order list of statements. */
export function flattenStatements(node: any, out: any[] = []): any[] {
  if (!node) return out;
  switch (node.type) {
    case 'Block':
      for (const s of node.statements ?? []) flattenStatements(s, out);
      break;
    case 'IfStatement':
      flattenStatements(node.trueBody, out);
      flattenStatements(node.falseBody, out);
      break;
    case 'ForStatement':
      flattenStatements(node.body, out);
      break;
    case 'WhileStatement':
    case 'DoWhileStatement':
      flattenStatements(node.body, out);
      break;
    case 'UncheckedStatement':
      for (const s of node.block?.statements ?? []) flattenStatements(s, out);
      break;
    default:
      out.push(node);
  }
  return out;
}

/**
 * `.call{value: x}(...)` wraps the callee MemberAccess in a NameValueExpression node
 * (older/alt grammars call this FunctionCallOptions) -- unwrap either.
 */
export function unwrapCallExpression(expr: any): any {
  if (expr?.type === 'NameValueExpression' || expr?.type === 'FunctionCallOptions') {
    return expr.expression;
  }
  return expr;
}

export function findExternalCalls(statement: any): { line: number; member: string; lowRisk: boolean }[] {
  const hits: { line: number; member: string; lowRisk: boolean }[] = [];
  parser.visit(statement, {
    FunctionCall(n: any) {
      const expr = unwrapCallExpression(n.expression);
      if (expr?.type === 'MemberAccess' && typeof expr.memberName === 'string') {
        if (EXTERNAL_CALL_MEMBERS.has(expr.memberName)) {
          hits.push({ line: n.loc?.start?.line ?? 0, member: expr.memberName, lowRisk: false });
        } else if (LOW_RISK_SEND_MEMBERS.has(expr.memberName)) {
          hits.push({ line: n.loc?.start?.line ?? 0, member: expr.memberName, lowRisk: true });
        }
      }
    },
  });
  return hits;
}

function baseIdentifierName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'IndexAccess') return baseIdentifierName(node.base);
  if (node.type === 'MemberAccess') return baseIdentifierName(node.expression);
  return null;
}

export function findStateVarWrites(
  statement: any,
  stateVars: Set<string>
): { line: number; name: string }[] {
  const hits: { line: number; name: string }[] = [];
  parser.visit(statement, {
    BinaryOperation(n: any) {
      if (ASSIGN_OPS.has(n.operator)) {
        const name = baseIdentifierName(n.left);
        if (name && stateVars.has(name)) {
          hits.push({ line: n.loc?.start?.line ?? 0, name });
        }
      }
    },
  });
  return hits;
}

export function hasSenderCheckModifierOrGuard(fn: any): boolean {
  if ((fn.modifiers ?? []).length > 0) return true;
  let found = false;
  parser.visit(fn.body, {
    FunctionCall(n: any) {
      if (n.expression?.type === 'Identifier' && n.expression.name === 'require') {
        const src = JSON.stringify(n.arguments ?? []);
        if (src.includes('msg.sender') || src.includes('owner') || src.includes('Owner')) found = true;
      }
    },
    MemberAccess(n: any) {
      if (n.memberName === 'onlyOwner') found = true;
    },
  });
  return found;
}
