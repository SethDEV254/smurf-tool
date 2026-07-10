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
