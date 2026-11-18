/**
 * CipherGuard AI - Test Binary Fixtures
 * Creates minimal valid PE structure headers for realistic test fixtures.
 */

export function createMockPeBuffer(customPayload = 'MZ test payload'): Buffer {
  // Minimal MZ header: 'MZ' magic bytes (0x4D, 0x5A) followed by PE pointer and payload
  const header = Buffer.alloc(64);
  header[0] = 0x4d; // 'M'
  header[1] = 0x5a; // 'Z'
  // Offset to PE signature at 0x3C
  header.writeInt32LE(0x40, 0x3c);

  const peSig = Buffer.from('PE\0\0'); // 4 bytes
  const payload = Buffer.from(customPayload, 'utf8');

  return Buffer.concat([header, peSig, payload]);
}
