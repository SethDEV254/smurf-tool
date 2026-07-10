import parser from '@solidity-parser/parser';

export function parseSolidity(source: string, filePath: string) {
  try {
    return parser.parse(source, { loc: true, range: true, tolerant: true });
  } catch (err) {
    throw new Error(`failed to parse ${filePath}: ${(err as Error).message}`);
  }
}

export function stateVarNames(contractNode: any): Set<string> {
  const names = new Set<string>();
  for (const sub of contractNode.subNodes ?? []) {
    if (sub.type === 'StateVariableDeclaration') {
      for (const v of sub.variables ?? []) {
        if (v?.name) names.add(v.name);
      }
    }
  }
  return names;
}

export function contractsOf(ast: any): any[] {
  return (ast.children ?? []).filter((n: any) => n.type === 'ContractDefinition');
}

export function functionsOf(contractNode: any): any[] {
  return (contractNode.subNodes ?? []).filter((n: any) => n.type === 'FunctionDefinition');
}

export function lineOf(node: any): number {
  return node?.loc?.start?.line ?? 0;
}

export function pragmaVersion(ast: any): string | null {
  for (const n of ast.children ?? []) {
    if (n.type === 'PragmaDirective' && n.name === 'solidity') return n.value;
  }
  return null;
}

/** True if a pragma string permits any compiler version below 0.8.0 (no built-in overflow checks). */
export function allowsPreCheckedArithmetic(pragma: string | null): boolean {
  if (!pragma) return false;
  const match = pragma.match(/0\.(\d+)\.\d+/);
  if (!match) return false;
  return Number(match[1]) < 8;
}
