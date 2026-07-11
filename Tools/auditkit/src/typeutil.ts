export function typeNameToString(t: any): string {
  if (!t) return 'unknown';
  switch (t.type) {
    case 'ElementaryTypeName':
      return t.name;
    case 'UserDefinedTypeName':
      return t.namePath;
    case 'ArrayTypeName':
      return `${typeNameToString(t.baseTypeName)}[]`;
    default:
      return t.type;
  }
}

export function isFuzzableElementary(t: any): boolean {
  return t?.type === 'ElementaryTypeName';
}

/** Dynamic types (`string`, `bytes`) need an explicit data location in a function signature. */
export function needsMemoryLocation(typeStr: string): boolean {
  return typeStr === 'string' || typeStr === 'bytes';
}

/** Best-effort zero/default value literal for a type, used to synthesize placeholder
 *  constructor args. Non-elementary types (structs, arrays) can't be synthesized generically
 *  and are left as an explicit TODO the caller must replace by hand. */
export function zeroValueForType(t: any): string {
  const typeStr = typeNameToString(t);
  if (t?.type === 'ElementaryTypeName') {
    if (/^u?int\d*$/.test(typeStr)) return '0';
    if (typeStr === 'address') return 'address(0)';
    if (typeStr === 'bool') return 'false';
    if (typeStr === 'bytes') return '""';
    if (/^bytes\d+$/.test(typeStr)) return `${typeStr}(0)`;
    if (typeStr === 'string') return '""';
  }
  return `/* TODO: fill in a real ${typeStr} value, this placeholder likely won't compile */ ${typeStr}(0)`;
}
