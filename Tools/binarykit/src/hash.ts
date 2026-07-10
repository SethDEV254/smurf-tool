export interface FileHashes {
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
}

export function hashFile(buf: Uint8Array): FileHashes {
  return {
    size: buf.length,
    md5: new Bun.CryptoHasher('md5').update(buf).digest('hex'),
    sha1: new Bun.CryptoHasher('sha1').update(buf).digest('hex'),
    sha256: new Bun.CryptoHasher('sha256').update(buf).digest('hex'),
  };
}
