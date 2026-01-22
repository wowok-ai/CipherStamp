import {
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from 'libsignal-protocol-typescript';
import type { StorageType, KeyPairType } from 'libsignal-protocol-typescript/lib/types';
import type { DeviceType } from 'libsignal-protocol-typescript/lib/session-types';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import http from 'http';
import {
  buildMessageAttestationBundle,
  MessageAttestationBundle,
  stampMessageAttestationBundle,
} from './validator';

const SERVER_URL = process.env.SERVER_URL ?? 'http://127.0.0.1:3000';
const DEFAULT_VALIDATOR_URL = process.env.VALIDATOR_URL ?? 'http://127.0.0.1:3103';
const LOCAL_USER = process.env.SENDER_ID ?? 'alice';
const REMOTE_USER = process.env.RECEIVER_ID ?? 'bob';
const DEVICE_ID = 1;
const DEFAULT_SENDER_AGENT_PORT = 3101;
const START_AGENT = process.argv.includes('--serve');
const SENDER_AGENT_PORT = START_AGENT
  ? resolvePort(process.env.SENDER_AGENT_PORT, DEFAULT_SENDER_AGENT_PORT)
  : 0;

type PersistedKeyPair = { pubKey: string; privKey: string };
type PersistedState = {
  identity?: PersistedKeyPair;
  registrationId?: number;
  identities: Record<string, string>;
  preKeys: Record<string, PersistedKeyPair>;
  signedPreKeys: Record<string, PersistedKeyPair>;
  sessions: Record<string, string>;
};

// 文件持久化存储，避免重启丢失会话/密钥
export class FileSignalStore implements StorageType {
  private state: PersistedState;
  private storePath: string;

  constructor(storePath = process.env.SIGNAL_STORE_PATH ?? path.resolve(__dirname, '../sender_store.json')) {
    this.storePath = storePath;
    this.state = this.loadFromDisk();
  }

  private loadFromDisk(): PersistedState {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, 'utf8');
        const parsed = JSON.parse(raw) as PersistedState;
        return { identities: {}, preKeys: {}, signedPreKeys: {}, sessions: {}, ...parsed };
      } catch {
        // ignore parse errors
      }
    }
    return { identities: {}, preKeys: {}, signedPreKeys: {}, sessions: {} };
  }

  private async persist() {
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    await fs.promises.writeFile(this.storePath, JSON.stringify(this.state, null, 2), 'utf8');
  }

  private toKeyPair(p?: PersistedKeyPair): KeyPairType | undefined {
    if (!p) return undefined;
    return { pubKey: b64ToArrayBuffer(p.pubKey), privKey: b64ToArrayBuffer(p.privKey) };
  }
  private fromKeyPair(pair: KeyPairType): PersistedKeyPair {
    return { pubKey: arrayBufferToB64(pair.pubKey), privKey: arrayBufferToB64(pair.privKey) };
  }

  async setIdentity(identity: KeyPairType, registrationId: number) {
    this.state.identity = this.fromKeyPair(identity);
    this.state.registrationId = registrationId;
    await this.persist();
  }
  async getIdentityKeyPair() {
    return this.toKeyPair(this.state.identity);
  }
  async getLocalRegistrationId() {
    return this.state.registrationId;
  }
  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction?: number) {
    const existing = this.state.identities[identifier];
    if (!existing) return true;
    return bufferEqual(b64ToArrayBuffer(existing), identityKey);
  }
  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer) {
    const existing = this.state.identities[encodedAddress];
    this.state.identities[encodedAddress] = arrayBufferToB64(publicKey);
    await this.persist();
    return existing ? bufferEqual(b64ToArrayBuffer(existing), publicKey) : true;
  }
  async loadPreKey(keyId: string | number) {
    return this.toKeyPair(this.state.preKeys[keyId.toString()]);
  }
  async storePreKey(keyId: string | number, keyPair: KeyPairType) {
    this.state.preKeys[keyId.toString()] = this.fromKeyPair(keyPair);
    await this.persist();
  }
  async removePreKey(keyId: string | number) {
    delete this.state.preKeys[keyId.toString()];
    await this.persist();
  }
  async storeSession(encodedAddress: string, record: string) {
    this.state.sessions[encodedAddress] = record;
    await this.persist();
  }
  async loadSession(encodedAddress: string) {
    return this.state.sessions[encodedAddress];
  }
  async loadSignedPreKey(keyId: string | number) {
    return this.toKeyPair(this.state.signedPreKeys[keyId.toString()]);
  }
  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType) {
    this.state.signedPreKeys[keyId.toString()] = this.fromKeyPair(keyPair);
    await this.persist();
  }
  async removeSignedPreKey(keyId: string | number) {
    delete this.state.signedPreKeys[keyId.toString()];
    await this.persist();
  }
}

type RemoteBundle = {
  registration_id: number;
  identity_key: string;
  signed_prekey: { key_id: number; public_key: string; signature: string };
  prekey?: { key_id: number; public_key: string };
};

type SenderConfig = {
  serverUrl?: string;
  fromUser?: string;
  toUser?: string;
  ttlSeconds?: number;
  messageId?: string;
  createdAt?: number;
  validatorUrl?: string;
};

// JSON 序列化的消息体
type OutgoingMessage = {
  id: string;
  from: string;
  to: string;
  msg_type: number;
  body_b64: string;
  registration_id?: number;
  ttl_seconds?: number;
  created_at?: number;
};

const encoder = new TextEncoder();

function bufferEqual(a: ArrayBuffer, b: ArrayBuffer) {
  if (a.byteLength !== b.byteLength) return false;
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  for (let i = 0; i < va.length; i += 1) {
    if (va[i] !== vb[i]) return false;
  }
  return true;
}

function b64ToArrayBuffer(b64: string) {
  return Uint8Array.from(Buffer.from(b64, 'base64')).buffer;
}

function arrayBufferToB64(buf: ArrayBuffer) {
  return Buffer.from(new Uint8Array(buf)).toString('base64');
}

function resolvePort(raw: string | undefined, fallback: number) {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function resolveSenderConfig(config: SenderConfig = {}) {
  if (config.fromUser && config.fromUser !== LOCAL_USER) {
    throw new Error(`sender configured for ${LOCAL_USER}, not ${config.fromUser}`);
  }
  const serverUrl = config.serverUrl ?? SERVER_URL;
  const fromUser = config.fromUser ?? LOCAL_USER;
  const toUser = config.toUser ?? REMOTE_USER;
  const validatorUrl = config.validatorUrl ?? DEFAULT_VALIDATOR_URL;
  return { serverUrl, fromUser, toUser, validatorUrl };
}

export async function ensureLocalIdentity(store: FileSignalStore) {
  const existing = await store.getIdentityKeyPair();
  const existingReg = await store.getLocalRegistrationId();
  if (existing && existingReg) return;

  const identity = await KeyHelper.generateIdentityKeyPair();
  const registrationId = KeyHelper.generateRegistrationId();
  await store.setIdentity(identity, registrationId);
}

async function fetchRemoteBundle(userId: string, config: SenderConfig = {}): Promise<RemoteBundle> {
  const { serverUrl } = resolveSenderConfig(config);
  const res = await fetch(`${serverUrl}/bundle/${userId}`);
  if (!res.ok) {
    throw new Error(`无法获取接收方密钥: ${res.statusText}`);
  }
  return (await res.json()) as RemoteBundle;
}

export function mapBundleToDevice(bundle: RemoteBundle): DeviceType<ArrayBuffer> {
  return {
    registrationId: bundle.registration_id,
    identityKey: b64ToArrayBuffer(bundle.identity_key),
    signedPreKey: {
      keyId: bundle.signed_prekey.key_id,
      publicKey: b64ToArrayBuffer(bundle.signed_prekey.public_key),
      signature: b64ToArrayBuffer(bundle.signed_prekey.signature),
    },
    preKey: bundle.prekey
      ? {
          keyId: bundle.prekey.key_id,
          publicKey: b64ToArrayBuffer(bundle.prekey.public_key),
        }
      : undefined,
  };
}

async function sendEncryptedMessage(text: string, config: SenderConfig = {}) {
  const store = new FileSignalStore();
  await ensureLocalIdentity(store);
  const { serverUrl, fromUser, toUser, validatorUrl } = resolveSenderConfig(config);

  // 拉取接收方的预键包，建立 Session
  const remoteBundle = await fetchRemoteBundle(toUser, { serverUrl });
  if (!remoteBundle.prekey) {
    throw new Error('接收方没有可用的一次性预键，可要求对方重新上传');
  }
  const device = mapBundleToDevice(remoteBundle);
  const remoteAddress = new SignalProtocolAddress(toUser, DEVICE_ID);
  const existingSession = await store.loadSession(remoteAddress.toString());
  if (!existingSession) {
    const builder = new SessionBuilder(store, remoteAddress);
    await builder.processPreKey(device);
  }

  // 发送第一条消息时返回的是 PreKeyWhisperMessage(type=3)
  // 生成密文的函数：SessionCipher.encrypt 会根据当前会话状态返回密文
  const cipher = new SessionCipher(store, remoteAddress);
  const cipherMessage = await cipher.encrypt(encoder.encode(text).buffer);
  const body_b64 = Buffer.from(cipherMessage.body ?? '', 'binary').toString('base64');

  const payload: OutgoingMessage = {
    id: config.messageId ?? randomUUID(),
    from: fromUser,
    to: toUser,
    msg_type: cipherMessage.type,
    registration_id: cipherMessage.registrationId,
    body_b64,
    created_at: config.createdAt ?? nowSeconds(),
    ttl_seconds: config.ttlSeconds,
  };

  const res = await fetch(`${serverUrl}/message`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`发送失败: ${res.statusText}`);
  }
  console.log('密文已投递给服务器，等待接收方拉取');

  let attestation = buildMessageAttestationBundle({
    plaintext: text,
    ciphertextBase64: payload.body_b64,
    senderId: fromUser,
    receiverId: toUser,
    createdAtMs: Date.now(),
    messageType: payload.msg_type,
    registrationId: payload.registration_id,
    deviceId: DEVICE_ID,
  });
  try {
    attestation = await stampMessageAttestationBundle(attestation);
  } catch (err) {
    warnOtsFailure(err);
  }
  await sendBundleToValidator(attestation, text, validatorUrl);
  return payload;
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

async function main() {
  if (SENDER_AGENT_PORT > 0) {
    startSenderAgent(SENDER_AGENT_PORT);
  }

  if (!START_AGENT) {
    const args = process.argv.slice(2);
    const textArg = args.find((arg) => arg !== '--serve');
    await sendEncryptedMessage(textArg ?? '你好，接收方！');
  }
}

function startSenderAgent(port: number) {
  const server = http.createServer(async (req, res) => {
    applyCors(res);
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    try {
      if (req.method === 'GET' && req.url === '/health') {
        sendJson(res, 200, { ok: true });
        return;
      }

      if (req.method === 'POST' && req.url === '/send') {
        const body = await readJsonBody(req);
        const plaintext = typeof body.plaintext === 'string' ? body.plaintext : '';
        if (!plaintext) {
          sendJson(res, 400, { error: 'plaintext is required' });
          return;
        }
        const ttlParsed =
          typeof body.ttlSeconds === 'number'
            ? body.ttlSeconds
            : typeof body.ttlSeconds === 'string'
              ? Number(body.ttlSeconds)
              : undefined;
        const config: SenderConfig = {
          serverUrl: body.serverUrl as string | undefined,
          fromUser: body.fromUser as string | undefined,
          toUser: body.toUser as string | undefined,
          ttlSeconds: Number.isFinite(ttlParsed) ? ttlParsed : undefined,
          messageId: (body.messageId as string | undefined) ?? (body.id as string | undefined),
          validatorUrl: body.validatorUrl as string | undefined,
        };
        const payload = await sendEncryptedMessage(plaintext, config);
        sendJson(res, 200, { ok: true, messageId: payload.id, msgType: payload.msg_type });
        return;
      }

      sendJson(res, 404, { error: 'Not Found' });
    } catch (err) {
      sendJson(res, 500, { error: err instanceof Error ? err.message : 'unknown error' });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`sender agent listening on http://127.0.0.1:${port}`);
  });
}

function applyCors(res: http.ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(payload));
}

function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total > 1_000_000) {
        reject(new Error('payload too large'));
      }
    });
    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

export { sendEncryptedMessage };

let validatorWarned = false;
let otsWarned = false;

async function sendBundleToValidator(
  bundle: MessageAttestationBundle,
  plaintext: string,
  validatorUrl: string | undefined,
) {
  if (!validatorUrl) return;
  try {
    await fetch(`${validatorUrl}/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ bundle, plaintext }),
    });
  } catch (err) {
    if (!validatorWarned) {
      validatorWarned = true;
      console.warn('validator send failed', err);
    }
  }
}

function warnOtsFailure(err: unknown) {
  if (otsWarned) return;
  otsWarned = true;
  console.warn('ots stamp failed', err);
}
