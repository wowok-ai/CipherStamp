import assert from 'assert';
import { parseInput, parseSalt } from '../src/timestampCiphertext';

function testParseInput() {
  const hexInput = 'deadbeef';
  const hexBuf = parseInput(hexInput, 'hex');
  assert.strictEqual(hexBuf.toString('hex'), hexInput);

  const b64Input = Buffer.from('hello').toString('base64');
  const b64Buf = parseInput(b64Input, 'base64');
  assert.strictEqual(b64Buf.toString('utf8'), 'hello');

  const utf8Input = 'plain text';
  const utf8Buf = parseInput(utf8Input, 'utf8');
  assert.strictEqual(utf8Buf.toString('utf8'), utf8Input);
}

function testParseSalt() {
  const hexSalt = '00010203';
  assert.strictEqual(parseSalt(hexSalt).toString('hex'), hexSalt);

  const b64Salt = Buffer.from('salt').toString('base64');
  assert.strictEqual(parseSalt(b64Salt).toString('utf8'), 'salt');

  const randomSalt = parseSalt();
  assert.strictEqual(randomSalt.length, 16, '默认随机盐长度应为16字节');
}

export async function run() {
  testParseInput();
  console.log('✔ timestampCiphertext parseInput 测试通过');

  testParseSalt();
  console.log('✔ timestampCiphertext parseSalt 测试通过');
}

if (require.main === module) {
  run().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
