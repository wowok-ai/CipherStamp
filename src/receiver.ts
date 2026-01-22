import {
  KeyHelper,
  SessionCipher,
  SignalProtocolAddress,
} from 'libsignal-protocol-typescript';
import type { StorageType, KeyPairType } from 'libsignal-protocol-typescript/lib/types';
import fs from 'fs';
import path from 'path';
import http from 'http';
import EventSource from 'eventsource';
import {
  buildMessageAttestationBundle,
  MessageAttestationBundle,
  stampMessageAttestationBundle,
} from './validator';

const SERVER_URL = process.env.SERVER_URL ?? 'http://127.0.0.1:3000';
const DEFAULT_VALIDATOR_URL = process.env.VALIDATOR_URL ?? 'http://127.0.0.1:3103';
const LOCAL_USER = process.env.RECEIVER_ID ?? 'bob';
const REMOTE_USER = process.env.SENDER_ID ?? 'alice';
const DEVICE_ID = 1;
const DEFAULT_RECEIVER_AGENT_PORT = 3102;
const START_AGENT = process.argv.includes('--serve');
const RECEIVER_AGENT_PORT = START_AGENT
  ? resolvePort(process.env.RECEIVER_AGENT_PORT, DEFAULT_RECEIVER_AGENT_PORT)
  : 0;
const PREKEY_BATCH_SIZE = resolveNumber(process.env.PREKEY_BATCH_SIZE, 20);
const PREKEY_MIN_AVAILABLE = resolveNumber(process.env.PREKEY_MIN_AVAILABLE, 5);
const PREKEY_TTL_SECONDS = resolveNumber(process.env.PREKEY_TTL_SECONDS, 60 * 60 * 24 * 7);
const SIGNED_PREKEY_TTL_SECONDS = resolveNumber(
  process.env.SIGNED_PREKEY_TTL_SECONDS,
  60 * 60 * 24 * 7,
);
const PREKEY_REFRESH_INTERVAL_SECONDS = resolveNumber(
  process.env.PREKEY_REFRESH_INTERVAL_SECONDS,
  60 * 30,
);

type PersistedKeyPair = { pubKey: string; privKey: string };
type PersistedPreKey = PersistedKeyPair & { createdAt?: number };
type PersistedSignedPreKey = PersistedKeyPair & { signature?: string; createdAt?: number };
type PersistedMeta = {
  nextPreKeyId: number;
  signedPreKeyId: number;
};

type PersistedState = {
  identity?: PersistedKeyPair;
  registrationId?: number;
  identities: Record<string, string>;
  preKeys: Record<string, PersistedPreKey>;
  signedPreKeys: Record<string, PersistedSignedPreKey>;
  sessions: Record<string, string>;
  meta: PersistedMeta;
};

// 文件持久化存储，避免重启丢失密钥材料
export class FileSignalStore implements StorageType {
  private state: PersistedState;
  private storePath: string;

  constructor(storePath = process.env.SIGNAL_STORE_PATH ?? path.resolve(__dirname, '../receiver_store.json')) {
    this.storePath = storePath;
    this.state = this.loadFromDisk();
  }

  private loadFromDisk(): PersistedState {
    if (fs.existsSync(this.storePath)) {
      try {
        const raw = fs.readFileSync(this.storePath, 'utf8');
        const parsed = JSON.parse(raw) as PersistedState;
        const defaults: PersistedState = {
          identities: {},
          preKeys: {},
          signedPreKeys: {},
          sessions: {},
          meta: { nextPreKeyId: 1, signedPreKeyId: 1 },
        };
        return {
          ...defaults,
          ...parsed,
          meta: { ...defaults.meta, ...parsed.meta },
        };
      } catch {
        // 读取失败则回落到空状态
      }
    }
    return {
      identities: {},
      preKeys: {},
      signedPreKeys: {},
      sessions: {},
      meta: { nextPreKeyId: 1, signedPreKeyId: 1 },
    };
  }

  private async persist() {
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    await fs.promises.writeFile(this.storePath, JSON.stringify(this.state, null, 2), 'utf8');
  }

  private toKeyPair(p?: PersistedKeyPair): KeyPairType | undefined {
    if (!p) return undefined;
    return {
      pubKey: base64ToArrayBuffer(p.pubKey),
      privKey: base64ToArrayBuffer(p.privKey),
    };
  }

  private fromKeyPair(pair: KeyPairType): PersistedKeyPair {
    return {
      pubKey: arrayBufferToB64(pair.pubKey),
      privKey: arrayBufferToB64(pair.privKey),
    };
  }

  async setIdentity(identity: KeyPairType, registrationId: number) {
    this.state.identity = this.fromKeyPair(identity);
    this.state.registrationId = registrationId;
    return this.persist();
  }

  async getIdentityKeyPair() {
    return this.toKeyPair(this.state.identity);
  }
  async getLocalRegistrationId() {
    return this.state.registrationId;
  }
  getMeta() {
    return this.state.meta;
  }
  async setMeta(meta: Partial<PersistedMeta>) {
    this.state.meta = { ...this.state.meta, ...meta };
    await this.persist();
  }
  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction?: number) {
    const existing = this.state.identities[identifier];
    if (!existing) return true;
    return bufferEqual(base64ToArrayBuffer(existing), identityKey);
  }
  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer) {
    const existing = this.state.identities[encodedAddress];
    this.state.identities[encodedAddress] = arrayBufferToB64(publicKey);
    await this.persist();
    return existing ? bufferEqual(base64ToArrayBuffer(existing), publicKey) : true;
  }
  async loadPreKey(keyId: string | number) {
    return this.toKeyPair(this.state.preKeys[keyId.toString()]);
  }
  async storePreKey(keyId: string | number, keyPair: KeyPairType) {
    const key = keyId.toString();
    const existing = this.state.preKeys[key];
    this.state.preKeys[key] = {
      ...this.fromKeyPair(keyPair),
      createdAt: existing?.createdAt ?? nowSeconds(),
    };
    await this.persist();
  }
  async storePreKeyWithCreatedAt(keyId: string | number, keyPair: KeyPairType, createdAt: number) {
    const key = keyId.toString();
    this.state.preKeys[key] = {
      ...this.fromKeyPair(keyPair),
      createdAt,
    };
    await this.persist();
  }
  async removePreKey(keyId: string | number) {
    delete this.state.preKeys[keyId.toString()];
    await this.persist();
  }
  listPreKeys() {
    return Object.entries(this.state.preKeys).map(([keyId, entry]) => ({
      keyId: Number(keyId),
      createdAt: entry.createdAt,
    }));
  }
  async pruneExpiredPreKeys(ttlSeconds: number) {
    const now = nowSeconds();
    let changed = false;
    for (const [keyId, entry] of Object.entries(this.state.preKeys)) {
      if (!entry.createdAt) {
        entry.createdAt = now;
        changed = true;
      }
      const createdAt = entry.createdAt ?? now;
      if (isExpired(createdAt, ttlSeconds, now)) {
        delete this.state.preKeys[keyId];
        changed = true;
      }
    }
    if (changed) {
      await this.persist();
    }
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
  getSignedPreKeySignature(keyId: string | number) {
    return this.state.signedPreKeys[keyId.toString()]?.signature;
  }
  getSignedPreKeyCreatedAt(keyId: string | number) {
    return this.state.signedPreKeys[keyId.toString()]?.createdAt;
  }
  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType) {
    const key = keyId.toString();
    const existing = this.state.signedPreKeys[key];
    this.state.signedPreKeys[key] = {
      ...this.fromKeyPair(keyPair),
      signature: existing?.signature,
      createdAt: existing?.createdAt ?? nowSeconds(),
    };
    await this.persist();
  }
  async storeSignedPreKeyWithSignature(
    keyId: string | number,
    keyPair: KeyPairType,
    signature: ArrayBuffer | Uint8Array,
    createdAt?: number,
  ) {
    const sigArray =
      signature instanceof ArrayBuffer
        ? new Uint8Array(signature)
        : new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength);
    const sigBuffer = Uint8Array.from(sigArray).buffer;
    const key = keyId.toString();
    const existing = this.state.signedPreKeys[key];
    this.state.signedPreKeys[keyId.toString()] = {
      ...this.fromKeyPair(keyPair),
      signature: arrayBufferToB64(sigBuffer),
      createdAt: createdAt ?? existing?.createdAt ?? nowSeconds(),
    };
    await this.persist();
  }
  async removeSignedPreKey(keyId: string | number) {
    delete this.state.signedPreKeys[keyId.toString()];
    await this.persist();
  }
}

type IncomingMessage = {
  id?: string;
  from: string;
  to: string;
  msg_type?: number;
  body_b64: string;
  registration_id?: number;
};

type DecryptedMessage = {
  id?: string;
  from: string;
  plaintext: string;
  msg_type?: number;
};

type ReceiverConfig = {
  serverUrl?: string;
  userId?: string;
  validatorUrl?: string;
};

const decoder = new TextDecoder();

function bufferEqual(a: ArrayBuffer, b: ArrayBuffer) {
  if (a.byteLength !== b.byteLength) return false;
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  for (let i = 0; i < va.length; i += 1) {
    if (va[i] !== vb[i]) return false;
  }
  return true;
}

function arrayBufferToB64(buf: ArrayBuffer) {
  return Buffer.from(new Uint8Array(buf)).toString('base64');
}

function base64ToArrayBuffer(b64: string) {
  return Uint8Array.from(Buffer.from(b64, 'base64')).buffer;
}

function resolveNumber(raw: string | undefined, fallback: number) {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resolvePort(raw: string | undefined, fallback: number) {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function isExpired(createdAt: number, ttlSeconds: number, now: number) {
  return now - createdAt >= ttlSeconds;
}

function resolveConfig(config: ReceiverConfig = {}) {
  if (config.userId && config.userId !== LOCAL_USER) {
    throw new Error(`receiver configured for ${LOCAL_USER}, not ${config.userId}`);
  }
  const serverUrl = config.serverUrl ?? SERVER_URL;
  const validatorUrl = config.validatorUrl ?? DEFAULT_VALIDATOR_URL;
  return { serverUrl, validatorUrl, userId: LOCAL_USER };
}

export async function ensureLocalIdentity(store: FileSignalStore) {
  const existing = await store.getIdentityKeyPair();
  const existingReg = await store.getLocalRegistrationId();
  if (existing && existingReg) return { identity: existing, registrationId: existingReg };

  const identity = await KeyHelper.generateIdentityKeyPair();
  const registrationId = KeyHelper.generateRegistrationId();
  await store.setIdentity(identity, registrationId);
  return { identity, registrationId };
}

async function ensureSignedPreKey(store: FileSignalStore, identity: KeyPairType) {
  const meta = store.getMeta();
  let signedPreKeyId = meta.signedPreKeyId || 1;
  let signedPreKeyPair = await store.loadSignedPreKey(signedPreKeyId);
  let signedPreKeySignature = store.getSignedPreKeySignature(signedPreKeyId);
  const createdAt = store.getSignedPreKeyCreatedAt(signedPreKeyId);
  const expired = createdAt ? isExpired(createdAt, SIGNED_PREKEY_TTL_SECONDS, nowSeconds()) : false;

  if (!signedPreKeyPair || !signedPreKeySignature || expired) {
    if (expired && signedPreKeyPair) {
      signedPreKeyId += 1;
    }
    const generated = await KeyHelper.generateSignedPreKey(identity, signedPreKeyId);
    signedPreKeyPair = generated.keyPair;
    signedPreKeySignature = arrayBufferToB64(generated.signature);
    await store.storeSignedPreKeyWithSignature(
      signedPreKeyId,
      signedPreKeyPair,
      generated.signature,
      nowSeconds(),
    );
    await store.setMeta({ signedPreKeyId });
  }

  if (!signedPreKeyPair || !signedPreKeySignature) {
    throw new Error('无法生成签名预键信息');
  }

  return { signedPreKeyId, signedPreKeyPair, signedPreKeySignature };
}

async function generatePreKeyBatch(store: FileSignalStore, count: number) {
  if (count <= 0) return [];
  const meta = store.getMeta();
  let nextPreKeyId = meta.nextPreKeyId || 1;
  const now = nowSeconds();
  const prekeys = [];

  for (let i = 0; i < count; i += 1) {
    const keyId = nextPreKeyId + i;
    const { keyPair } = await KeyHelper.generatePreKey(keyId);
    await store.storePreKeyWithCreatedAt(keyId, keyPair, now);
    prekeys.push({
      key_id: keyId,
      public_key: arrayBufferToB64(keyPair.pubKey),
      created_at: now,
      ttl_seconds: PREKEY_TTL_SECONDS,
    });
  }

  nextPreKeyId += count;
  await store.setMeta({ nextPreKeyId });
  return prekeys;
}

async function uploadPreKeys(
  store: FileSignalStore,
  config: ReceiverConfig,
  prekeys: Array<{ key_id: number; public_key: string; created_at: number; ttl_seconds: number }>,
) {
  if (!prekeys.length) return;
  const { serverUrl, userId } = resolveConfig(config);
  const payload = {
    user_id: userId,
    prekeys,
  };
  const res = await fetch(`${serverUrl}/prekeys/upload`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`预键上传失败: ${res.statusText}`);
  }
}

async function ensurePreKeys(store: FileSignalStore, config: ReceiverConfig, force = false) {
  await store.pruneExpiredPreKeys(PREKEY_TTL_SECONDS);
  const now = nowSeconds();
  const available = store
    .listPreKeys()
    .filter((entry) => !isExpired(entry.createdAt ?? now, PREKEY_TTL_SECONDS, now)).length;

  if (!force && available >= PREKEY_MIN_AVAILABLE) {
    return { available, uploaded: 0 };
  }

  const batchSize = Math.max(PREKEY_BATCH_SIZE, PREKEY_MIN_AVAILABLE);
  const prekeys = await generatePreKeyBatch(store, batchSize);
  await uploadPreKeys(store, config, prekeys);
  return { available: available + prekeys.length, uploaded: prekeys.length };
}

async function registerDevice(store: FileSignalStore, config: ReceiverConfig = {}) {
  const { identity, registrationId } = await ensureLocalIdentity(store);
  const { signedPreKeyId, signedPreKeyPair, signedPreKeySignature } = await ensureSignedPreKey(
    store,
    identity,
  );
  const prekeys = await generatePreKeyBatch(store, PREKEY_BATCH_SIZE);

  const { serverUrl, userId } = resolveConfig(config);
  const payload = {
    user_id: userId,
    registration_id: registrationId,
    identity_key: arrayBufferToB64(identity.pubKey),
    signed_prekey: {
      key_id: signedPreKeyId,
      public_key: arrayBufferToB64(signedPreKeyPair.pubKey),
      signature: signedPreKeySignature,
    },
    prekeys,
  };

  const res = await fetch(`${serverUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`注册失败: ${res.statusText}`);
  }
  console.log('预键信息已上传服务器，等待发送方拉取');
}

async function pullAndDecryptMessages(
  store: FileSignalStore,
  config: ReceiverConfig = {},
): Promise<DecryptedMessage[]> {
  const { serverUrl, validatorUrl, userId } = resolveConfig(config);
  const res = await fetch(`${serverUrl}/messages/${userId}`);
  if (!res.ok) {
    throw new Error(`读取消息失败: ${res.statusText}`);
  }
  const messages = (await res.json()) as IncomingMessage[];
  if (!messages.length) {
    return [];
  }

  const out: DecryptedMessage[] = [];
  for (const msg of messages) {
    const remoteId = msg.from ?? REMOTE_USER;
    const remoteAddress = new SignalProtocolAddress(remoteId, DEVICE_ID);
    const cipher = new SessionCipher(store, remoteAddress);
    const rawBody = Buffer.from(msg.body_b64, 'base64').toString('binary');
    const msgType = msg.msg_type ?? 3;
    const plaintextBuffer =
      msgType === 3
        ? await cipher.decryptPreKeyWhisperMessage(rawBody, 'binary')
        : await cipher.decryptWhisperMessage(rawBody, 'binary');
    const plaintext = decoder.decode(plaintextBuffer);
    let bundle = buildMessageAttestationBundle({
      plaintext,
      ciphertextBase64: msg.body_b64,
      senderId: remoteId,
      receiverId: msg.to,
      createdAtMs: Date.now(),
      messageType: msg.msg_type,
      registrationId: msg.registration_id,
      deviceId: DEVICE_ID,
    });
    try {
      bundle = await stampMessageAttestationBundle(bundle);
    } catch (err) {
      warnOtsFailure(err);
    }
    await sendBundleToValidator(bundle, plaintext, validatorUrl);
    out.push({
      id: msg.id,
      from: remoteId,
      plaintext,
      msg_type: msg.msg_type,
    });
  }

  return out;
}

export async function pullAndDecrypt(store: FileSignalStore, config: ReceiverConfig = {}) {
  const messages = await pullAndDecryptMessages(store, config);
  if (!messages.length) {
    console.log('暂无新消息');
    return [];
  }

  for (const msg of messages) {
    console.log(`收到来自 ${msg.from} 的明文: ${msg.plaintext}`);
  }
  await ensurePreKeys(store, config);
  return messages;
}

async function main() {
  const store = new FileSignalStore();
  await registerDevice(store);
  await ensurePreKeys(store, {});
  await pullAndDecrypt(store);
  startEventStream(store);
  schedulePreKeyRefresh(store);
  if (RECEIVER_AGENT_PORT > 0) {
    startReceiverAgent(store, RECEIVER_AGENT_PORT);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

function startEventStream(store: FileSignalStore) {
  const es = new EventSource(`${SERVER_URL}/events/${LOCAL_USER}`);
  let busy = false;

  es.onmessage = async (ev) => {
    if (busy) return;
    busy = true;
    try {
      const data = JSON.parse(ev.data) as { kind?: string };
      if (data.kind === 'NEW_MSG') {
        await pullAndDecrypt(store);
      }
    } catch (err) {
      // ignore parse errors
    } finally {
      busy = false;
    }
  };

  es.onerror = () => {
    // SSE 断线后由 eventsource 自动重连，无需额外处理
  };
}

function schedulePreKeyRefresh(store: FileSignalStore) {
  if (PREKEY_REFRESH_INTERVAL_SECONDS <= 0) return;
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try {
      const rotated = await refreshSignedPreKeyIfNeeded(store, {}, false);
      if (!rotated) {
        await ensurePreKeys(store, {});
      }
    } catch (err) {
      console.error('prekey refresh failed', err);
    } finally {
      running = false;
    }
  }, PREKEY_REFRESH_INTERVAL_SECONDS * 1000);
}

async function refreshSignedPreKeyIfNeeded(
  store: FileSignalStore,
  config: ReceiverConfig,
  force: boolean,
) {
  const identity = await store.getIdentityKeyPair();
  const registrationId = await store.getLocalRegistrationId();
  if (!identity || !registrationId) {
    await registerDevice(store, config);
    return true;
  }

  const meta = store.getMeta();
  const signedPreKeyId = meta.signedPreKeyId || 1;
  const createdAt = store.getSignedPreKeyCreatedAt(signedPreKeyId);
  const now = nowSeconds();
  const expired = createdAt ? isExpired(createdAt, SIGNED_PREKEY_TTL_SECONDS, now) : true;

  if (force || expired) {
    await registerDevice(store, config);
    return true;
  }
  return false;
}

function startReceiverAgent(store: FileSignalStore, port: number) {
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

      if (req.method === 'POST' && req.url === '/messages/pull') {
        const body = await readJsonBody(req);
        const config = {
          serverUrl: body.serverUrl as string | undefined,
          userId: body.userId as string | undefined,
          validatorUrl: body.validatorUrl as string | undefined,
        };
        const messages = await pullAndDecryptMessages(store, config);
        sendJson(res, 200, { messages });
        return;
      }

      if (req.method === 'POST' && req.url === '/prekeys/refresh') {
        const body = await readJsonBody(req);
        const config = {
          serverUrl: body.serverUrl as string | undefined,
          userId: body.userId as string | undefined,
          validatorUrl: body.validatorUrl as string | undefined,
        };
        const result = await ensurePreKeys(store, config, Boolean(body.force));
        sendJson(res, 200, { ok: true, ...result });
        return;
      }

      if (req.method === 'POST' && req.url === '/register') {
        const body = await readJsonBody(req);
        const config = {
          serverUrl: body.serverUrl as string | undefined,
          userId: body.userId as string | undefined,
          validatorUrl: body.validatorUrl as string | undefined,
        };
        await registerDevice(store, config);
        sendJson(res, 200, { ok: true });
        return;
      }

      if (req.method === 'POST' && req.url === '/signed-prekey/refresh') {
        const body = await readJsonBody(req);
        const config = {
          serverUrl: body.serverUrl as string | undefined,
          userId: body.userId as string | undefined,
          validatorUrl: body.validatorUrl as string | undefined,
        };
        const rotated = await refreshSignedPreKeyIfNeeded(store, config, true);
        sendJson(res, 200, { ok: true, rotated });
        return;
      }

      sendJson(res, 404, { error: 'Not Found' });
    } catch (err) {
      sendJson(res, 500, { error: err instanceof Error ? err.message : 'unknown error' });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`receiver agent listening on http://127.0.0.1:${port}`);
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
