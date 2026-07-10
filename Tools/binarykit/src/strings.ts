export interface ExtractedString {
  offset: number;
  value: string;
  encoding: 'ascii' | 'utf16le';
}

export interface FlaggedStrings {
  urls: string[];
  ips: string[];
  suspiciousApis: string[];
  licensingHints: string[];
}

const MIN_LEN = 4;

function isPrintable(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

// String.fromCharCode(...bytes) blows the call stack on large spreads (e.g. a big
// embedded text resource read as one "printable" run), so batch it.
const SPREAD_CHUNK = 8192;
function charCodesToString(codes: ArrayLike<number>): string {
  let out = '';
  for (let i = 0; i < codes.length; i += SPREAD_CHUNK) {
    out += String.fromCharCode(...Array.prototype.slice.call(codes, i, i + SPREAD_CHUNK));
  }
  return out;
}

// Bun's TextDecoder only actually supports UTF-8 regardless of the label passed in,
// so for these byte-range-constrained (printable ASCII) runs we build strings
// directly from char codes rather than going through TextDecoder.

function extractAscii(buf: Uint8Array, minLen: number): ExtractedString[] {
  const out: ExtractedString[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const printable = i < buf.length && isPrintable(buf[i]);
    if (printable) {
      if (start === -1) start = i;
    } else if (start !== -1) {
      const len = i - start;
      if (len >= minLen) {
        out.push({
          offset: start,
          value: charCodesToString(buf.subarray(start, i)),
          encoding: 'ascii',
        });
      }
      start = -1;
    }
  }
  return out;
}

function extractUtf16le(buf: Uint8Array, minLen: number): ExtractedString[] {
  const out: ExtractedString[] = [];
  let start = -1;
  const chars: number[] = [];
  const flush = () => {
    if (start !== -1 && chars.length >= minLen) {
      out.push({ offset: start, value: charCodesToString(chars), encoding: 'utf16le' });
    }
    start = -1;
    chars.length = 0;
  };

  for (let i = 0; i + 1 < buf.length; i += 2) {
    const lo = buf[i];
    const hi = buf[i + 1];
    if (hi === 0x00 && isPrintable(lo)) {
      if (start === -1) start = i;
      chars.push(lo);
    } else {
      flush();
    }
  }
  flush();
  return out;
}

export function extractStrings(buf: Uint8Array, minLen = MIN_LEN): ExtractedString[] {
  return [...extractAscii(buf, minLen), ...extractUtf16le(buf, minLen)].sort((a, b) => a.offset - b.offset);
}

const SUSPICIOUS_APIS = [
  'VirtualAlloc',
  'VirtualProtect',
  'CreateRemoteThread',
  'WriteProcessMemory',
  'ReadProcessMemory',
  'SetWindowsHookEx',
  'IsDebuggerPresent',
  'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess',
  'LoadLibrary',
  'GetProcAddress',
  'ptrace',
  'LD_PRELOAD',
  'dlopen',
  '/bin/sh',
  'cmd.exe',
  'powershell',
  'RegCreateKey',
  'RegSetValue',
  'CryptEncrypt',
  'InternetOpen',
  'WinExec',
  'ShellExecute',
];

const LICENSING_KEYWORDS = [
  'license',
  'licence',
  'trial',
  'expired',
  'expiration',
  'serial',
  'activation',
  'registration',
  'unlock',
  'genuine',
  'validate',
  'checksum',
];

export function flagStrings(strings: ExtractedString[]): FlaggedStrings {
  const urls = new Set<string>();
  const ips = new Set<string>();
  const suspiciousApis = new Set<string>();
  const licensingHints = new Set<string>();

  const urlRe = /\bhttps?:\/\/[^\s"'<>]+/i;
  const ipRe = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

  for (const s of strings) {
    const v = s.value;
    const urlMatch = v.match(urlRe);
    if (urlMatch) urls.add(urlMatch[0]);
    const ipMatch = v.match(ipRe);
    if (ipMatch) ips.add(ipMatch[0]);
    for (const api of SUSPICIOUS_APIS) {
      if (v.includes(api)) suspiciousApis.add(api);
    }
    const lower = v.toLowerCase();
    for (const kw of LICENSING_KEYWORDS) {
      if (lower.includes(kw)) licensingHints.add(v.length <= 80 ? v : `${v.slice(0, 80)}...`);
    }
  }

  return {
    urls: [...urls],
    ips: [...ips],
    suspiciousApis: [...suspiciousApis],
    licensingHints: [...licensingHints].slice(0, 50),
  };
}
