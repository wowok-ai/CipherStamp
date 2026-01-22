import fs from 'fs';
import path from 'path';
import { createHash, randomBytes } from 'crypto';
import * as OpenTimestamps from 'opentimestamps';
import { DetachedTimestampFile, Ops } from 'opentimestamps';

type InputEncoding = BufferEncoding | 'utf8';

export function parseInput(input: string, encoding: InputEncoding): Buffer {
  if (encoding === 'hex' || encoding === 'base64') {
    return Buffer.from(input, encoding);
  }
  return Buffer.from(input, 'utf8');
}

export function parseSalt(raw?: string): Buffer {
  if (!raw) return randomBytes(16);

  const hexLike = /^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0;
  if (hexLike) {
    return Buffer.from(raw, 'hex');
  }

  try {
    return Buffer.from(raw, 'base64');
  } catch (err) {
    throw new Error('盐格式不合法，需为 hex 或 base64');
  }
}

async function main() {
  const [, , cipherArg, maybeEncoding, maybeOutput] = process.argv;
  if (!cipherArg) {
    console.error(
      '用法：pnpm ts-node src/timestampCiphertext.ts <ciphertext> [hex|base64|utf8] [outputPath]',
    );
    process.exit(1);
  }

  const isEncoding = maybeEncoding === 'hex' || maybeEncoding === 'base64' || maybeEncoding === 'utf8';
  const encoding: InputEncoding = isEncoding ? (maybeEncoding as InputEncoding) : 'utf8';
  const outputArg = isEncoding ? maybeOutput : maybeEncoding;
  const ciphertext = parseInput(cipherArg, encoding);

  // 显式加盐后再做哈希，避免裸数据哈希上链
  const salt = parseSalt(process.env.OTS_SALT);
  const saltHex = salt.toString('hex');
  const saltedHash = createHash('sha256').update(Buffer.concat([salt, ciphertext])).digest();
  const saltedHashHex = saltedHash.toString('hex');
  console.log(`使用盐 (hex): ${saltHex}`);
  console.log(`加盐密文哈希 (sha256, hex): ${saltedHashHex}`);

  // 使用 OpenTimestamps 将哈希提交到公共日历，生成链上时间戳证明
  const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), saltedHash);
  try {
    await OpenTimestamps.stamp(detached);
  } catch (err) {
    console.error('调用 OpenTimestamps 日历失败:', err);
    process.exit(1);
  }

  const proof = Buffer.from(detached.serializeToBytes());
  const outputPath = outputArg
    ? path.resolve(outputArg)
    : path.resolve(process.cwd(), `${saltedHashHex}.ots`);
  fs.writeFileSync(outputPath, proof);

  console.log(`时间戳凭证已写入: ${outputPath}`);
  const meta = {
    saltHex,
    saltedHashHex,
    ciphertextEncoding: encoding,
    receiptFile: path.basename(outputPath),
    note: '验证时需使用 salt + ciphertext 做同样的 sha256，以匹配 ots 凭证',
  };
  const metaPath = `${outputPath}.json`;
  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
  console.log(`验证元数据已写入: ${metaPath}`);
  console.log('提示：可用 ots-cli.js verify <凭证> 校验，或调用 OpenTimestamps.upgrade 进一步升级证明。');
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
