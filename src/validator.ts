import { createHash, randomBytes } from 'crypto';
import * as OpenTimestamps from 'opentimestamps';
import { DetachedTimestampFile, Ops } from 'opentimestamps';

export type HashHex = string;

export interface MessageAttestationBundle {
  // 业务层：明文哈希，便于调用方在解密后比对
  plaintextHashHex: HashHex;
  // libsignal 生成的密文（base64），用于复算哈希链
  ciphertextBase64: string;
  // sha256(ciphertext) 的十六进制，用于快速一致性校验
  ciphertextHashHex: HashHex;
  // 上链前使用的盐
  saltHex: HashHex;
  // sha256(salt || ciphertext) 的结果，应与 ots 凭证对应
  saltedCiphertextHashHex: HashHex;
  // OpenTimestamps 凭证的 base64 编码（DetachedTimestampFile 序列化后的二进制）
  otsReceiptBase64: string;
  // 可选：身份与时间信息，帮助在链路中定位
  senderId?: string;
  receiverId?: string;
  createdAtMs?: number;
  // 会话/握手元数据（便于复查/追责，不含解密材料）
  messageType?: number; // 3=PreKeyWhisper，1/2=Whisper
  senderEphemeralKeyBase64?: string;
  preKeyId?: number;
  signedPreKeyId?: number;
  registrationId?: number;
  deviceId?: number;
}

export type BuildBundleInput = {
  plaintext: string | Buffer;
  ciphertextBase64: string;
  saltHex?: string;
  otsReceiptBase64?: string;
  senderId?: string;
  receiverId?: string;
  createdAtMs?: number;
  messageType?: number;
  senderEphemeralKeyBase64?: string;
  preKeyId?: number;
  signedPreKeyId?: number;
  registrationId?: number;
  deviceId?: number;
};

function sha256Hex(buf: Buffer) {
  return createHash('sha256').update(buf).digest('hex');
}

export function hashPlaintext(plaintext: string | Buffer): HashHex {
  const payload = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : Buffer.from(plaintext);
  return sha256Hex(payload);
}

export function hashCiphertextBase64(ciphertextBase64: string): HashHex {
  const cipher = Buffer.from(ciphertextBase64, 'base64');
  return sha256Hex(cipher);
}

export function hashSaltedCiphertext(ciphertextBase64: string, saltHex: string): HashHex {
  const cipher = Buffer.from(ciphertextBase64, 'base64');
  const salt = Buffer.from(saltHex, 'hex');
  return sha256Hex(Buffer.concat([salt, cipher]));
}

export function buildMessageAttestationBundle(input: BuildBundleInput): MessageAttestationBundle {
  const plaintextHashHex = hashPlaintext(input.plaintext);
  const ciphertextHashHex = hashCiphertextBase64(input.ciphertextBase64);
  const saltHex = input.saltHex ?? randomBytes(16).toString('hex');
  const saltedCiphertextHashHex = hashSaltedCiphertext(input.ciphertextBase64, saltHex);

  return {
    plaintextHashHex,
    ciphertextBase64: input.ciphertextBase64,
    ciphertextHashHex,
    saltHex,
    saltedCiphertextHashHex,
    otsReceiptBase64: input.otsReceiptBase64 ?? '',
    senderId: input.senderId,
    receiverId: input.receiverId,
    createdAtMs: input.createdAtMs,
    messageType: input.messageType,
    senderEphemeralKeyBase64: input.senderEphemeralKeyBase64,
    preKeyId: input.preKeyId,
    signedPreKeyId: input.signedPreKeyId,
    registrationId: input.registrationId,
    deviceId: input.deviceId,
  };
}

export async function stampMessageAttestationBundle(
  bundle: MessageAttestationBundle,
): Promise<MessageAttestationBundle> {
  const detached = DetachedTimestampFile.fromHash(
    new Ops.OpSHA256(),
    Buffer.from(bundle.saltedCiphertextHashHex, 'hex'),
  );
  await OpenTimestamps.stamp(detached);
  const receipt = Buffer.from(detached.serializeToBytes()).toString('base64');
  return { ...bundle, otsReceiptBase64: receipt };
}

export async function buildStampedMessageAttestationBundle(
  input: BuildBundleInput,
): Promise<MessageAttestationBundle> {
  const bundle = buildMessageAttestationBundle(input);
  return stampMessageAttestationBundle(bundle);
}

type VerifyOptions = {
  plaintext?: string | Buffer;
  // 如果外部持有独立的密文版本，可传入覆盖 bundle 中的 ciphertextBase64
  ciphertextBase64?: string;
  // 避免阻塞过久，默认 5s；网络环境受限时可传更大
  timeoutMs?: number;
  ignoreBitcoinNode?: boolean;
};

export type VerifyResult = {
  plaintextHashOk: boolean;
  ciphertextHashOk: boolean;
  saltedHashOk: boolean;
  otsVerified: boolean;
  otsDetails?: Awaited<ReturnType<typeof OpenTimestamps.verify>>;
};

export async function verifyMessageAttestation(
  bundle: MessageAttestationBundle,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const {
    plaintext,
    ciphertextBase64 = bundle.ciphertextBase64,
    timeoutMs = 5000,
    ignoreBitcoinNode = true,
  } = options;

  // 1) 明文链路：仅在提供 plaintext 时校验
  const plaintextHashOk = plaintext
    ? hashPlaintext(plaintext) === bundle.plaintextHashHex
    : false;

  // 2) 密文链路：校验密文哈希
  const ciphertextHashOk = hashCiphertextBase64(ciphertextBase64) === bundle.ciphertextHashHex;

  // 3) 加盐哈希链路：校验 salt + 密文 的哈希
  const saltedHashOk =
    hashSaltedCiphertext(ciphertextBase64, bundle.saltHex) === bundle.saltedCiphertextHashHex;

  // 4) OTS 链路：验证链上时间戳证明
  let otsVerified = false;
  let otsDetails: Awaited<ReturnType<typeof OpenTimestamps.verify>> | undefined;

  if (bundle.otsReceiptBase64) {
    try {
      const receiptBytes = Buffer.from(bundle.otsReceiptBase64, 'base64');
      const stamped = DetachedTimestampFile.deserialize(receiptBytes);
      const original = DetachedTimestampFile.fromHash(
        new Ops.OpSHA256(),
        Buffer.from(bundle.saltedCiphertextHashHex, 'hex'),
      );
      otsDetails = await OpenTimestamps.verify(stamped, original, {
        timeout: timeoutMs,
        ignoreBitcoinNode,
      });
      otsVerified = !!otsDetails;
    } catch (err) {
      otsVerified = false;
    }
  }

  return {
    plaintextHashOk,
    ciphertextHashOk,
    saltedHashOk,
    otsVerified,
    otsDetails,
  };
}
