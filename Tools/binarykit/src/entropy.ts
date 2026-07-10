export interface EntropyChunk {
  offset: number;
  length: number;
  entropy: number;
}

export interface EntropyReport {
  overall: number;
  chunkSize: number;
  highEntropyChunks: EntropyChunk[];
  likelyPacked: boolean;
}

function shannonEntropy(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const b of buf) counts[b]++;
  let entropy = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / buf.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const HIGH_ENTROPY_THRESHOLD = 7.5; // bits/byte, out of a max of 8
const CHUNK_SIZE = 4096;

export function analyzeEntropy(buf: Uint8Array, chunkSize = CHUNK_SIZE): EntropyReport {
  const overall = shannonEntropy(buf);
  const highEntropyChunks: EntropyChunk[] = [];

  for (let offset = 0; offset < buf.length; offset += chunkSize) {
    const chunk = buf.subarray(offset, Math.min(offset + chunkSize, buf.length));
    const entropy = shannonEntropy(chunk);
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      highEntropyChunks.push({ offset, length: chunk.length, entropy: Number(entropy.toFixed(3)) });
    }
  }

  // A handful of scattered high-entropy chunks is normal (compressed resources,
  // crypto constants). Flag as "likely packed" only when most of the file is dense.
  const highEntropyBytes = highEntropyChunks.reduce((sum, c) => sum + c.length, 0);
  const likelyPacked = buf.length > 0 && highEntropyBytes / buf.length > 0.6;

  return { overall: Number(overall.toFixed(3)), chunkSize, highEntropyChunks, likelyPacked };
}
