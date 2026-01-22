import assert from 'assert';
import { createHash } from 'crypto';
import { hashPlaintext, hashCiphertextBase64, hashSaltedCiphertext } from '../src/validator';

function sha256Hex(buf: Buffer) {
  return createHash('sha256').update(buf).digest('hex');
}

function testHashPlaintext() {
  const input = 'hello';
  const expected = sha256Hex(Buffer.from(input, 'utf8'));
  const got = hashPlaintext(input);
  assert.strictEqual(got, expected, 'hashPlaintext 应与 sha256(utf8) 一致');
}

function testHashCiphertextBase64() {
  const plaintext = 'hello';
  const ciphertextB64 = Buffer.from(plaintext, 'utf8').toString('base64'); // 模拟已加密后的 base64 内容
  const expected = sha256Hex(Buffer.from(plaintext, 'utf8'));
  const got = hashCiphertextBase64(ciphertextB64);
  assert.strictEqual(got, expected, 'hashCiphertextBase64 应与 sha256(解码后的字节) 一致');
}

function testHashSaltedCiphertext() {
  const plaintext = 'hello';
  const ciphertextB64 = Buffer.from(plaintext, 'utf8').toString('base64');
  const saltHex = '00010203';
  const salt = Buffer.from(saltHex, 'hex');
  const expected = sha256Hex(Buffer.concat([salt, Buffer.from(plaintext, 'utf8')]));
  const got = hashSaltedCiphertext(ciphertextB64, saltHex);
  assert.strictEqual(got, expected, 'hashSaltedCiphertext 应与 sha256(salt || bytes) 一致');
}

export async function run() {
  const tests: Array<[string, () => void | Promise<void>]> = [
    ['hashPlaintext', testHashPlaintext],
    ['hashCiphertextBase64', testHashCiphertextBase64],
    ['hashSaltedCiphertext', testHashSaltedCiphertext],
  ];

  for (const [name, fn] of tests) {
    await fn();
    console.log(`✔ ${name} 通过`);
  }
  console.log('所有 validator 哈希函数测试通过');
}

if (require.main === module) {
  run().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
