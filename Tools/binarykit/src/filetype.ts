export interface FileTypeInfo {
  format: 'ELF' | 'PE' | 'Mach-O' | 'Mach-O (fat)' | 'script' | 'text' | 'unknown';
  bitness?: 32 | 64;
  endianness?: 'LE' | 'BE';
  arch?: string;
  interpreter?: string;
}

const ELF_MACHINE: Record<number, string> = {
  0x03: 'x86',
  0x28: 'ARM',
  0x3e: 'x86-64',
  0xb7: 'AArch64',
  0xf3: 'RISC-V',
};

const PE_MACHINE: Record<number, string> = {
  0x014c: 'x86',
  0x0200: 'IA64',
  0x8664: 'x86-64',
  0x01c0: 'ARM',
  0xaa64: 'ARM64',
};

function readShebang(buf: Uint8Array): string | null {
  if (buf[0] !== 0x23 || buf[1] !== 0x21) return null; // "#!"
  const end = buf.indexOf(0x0a, 2);
  const bytes = buf.subarray(2, end === -1 ? Math.min(buf.length, 128) : end);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim();
}

function looksLikeText(buf: Uint8Array): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  let nonPrintable = 0;
  for (const b of sample) {
    if (b === 0) return false;
    if (b < 9 || (b > 13 && b < 32)) nonPrintable++;
  }
  return nonPrintable / sample.length < 0.05;
}

export function detectFileType(buf: Uint8Array): FileTypeInfo {
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    const bitness = buf[4] === 2 ? 64 : 32;
    const endianness = buf[5] === 2 ? 'BE' : 'LE';
    const machineOffset = 18;
    const machine =
      endianness === 'LE'
        ? buf[machineOffset] | (buf[machineOffset + 1] << 8)
        : (buf[machineOffset] << 8) | buf[machineOffset + 1];
    return { format: 'ELF', bitness, endianness, arch: ELF_MACHINE[machine] ?? `unknown(0x${machine.toString(16)})` };
  }

  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const lfanew = buf.length >= 0x40 ? buf[0x3c] | (buf[0x3d] << 8) | (buf[0x3e] << 16) | (buf[0x3f] << 24) : 0;
    if (lfanew > 0 && lfanew + 6 <= buf.length && buf[lfanew] === 0x50 && buf[lfanew + 1] === 0x45) {
      const machine = buf[lfanew + 4] | (buf[lfanew + 5] << 8);
      const bitness = machine === 0x8664 || machine === 0xaa64 || machine === 0x0200 ? 64 : 32;
      return { format: 'PE', bitness, endianness: 'LE', arch: PE_MACHINE[machine] ?? `unknown(0x${machine.toString(16)})` };
    }
    return { format: 'PE', arch: 'unknown (DOS stub only or truncated)' };
  }

  if (buf.length >= 4) {
    // >>> 0 forces unsigned interpretation -- plain `<<`/`|` overflow into the sign
    // bit for magic bytes >= 0x80 (e.g. 0xfe), producing a negative number that can
    // never equal the positive 0xfeedface-style literals below.
    const magic = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
    if (magic === 0xcafebabe || magic === 0xbebafeca) {
      return { format: 'Mach-O (fat)' };
    }
    if (magic === 0xfeedface || magic === 0xcefaedfe) {
      return { format: 'Mach-O', bitness: 32, endianness: magic === 0xfeedface ? 'BE' : 'LE' };
    }
    if (magic === 0xfeedfacf || magic === 0xcffaedfe) {
      return { format: 'Mach-O', bitness: 64, endianness: magic === 0xfeedfacf ? 'BE' : 'LE' };
    }
  }

  const interpreter = readShebang(buf);
  if (interpreter) return { format: 'script', interpreter };

  if (looksLikeText(buf)) return { format: 'text' };

  return { format: 'unknown' };
}
