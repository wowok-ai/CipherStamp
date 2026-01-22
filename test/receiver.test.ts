import assert from 'assert';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { KeyHelper } from 'libsignal-protocol-typescript';
import { FileSignalStore, ensureLocalIdentity } from '../src/receiver';

function tmpFile(name: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wowok-receiver-'));
  return path.join(dir, name);
}

async function testEnsureLocalIdentityPersists() {
  const storePath = tmpFile('store.json');
  const store = new FileSignalStore(storePath);

  const first = await ensureLocalIdentity(store);
  assert.ok(first.identity && first.registrationId, '应生成身份与 registrationId');

  const second = await ensureLocalIdentity(store);
  assert.strictEqual(
    Buffer.from(first.identity!.pubKey as ArrayBuffer).toString('base64'),
    Buffer.from(second.identity!.pubKey as ArrayBuffer).toString('base64'),
    '重复调用应复用已有身份',
  );
  assert.strictEqual(first.registrationId, second.registrationId, 'registrationId 应保持一致');
}

async function testSignedPreKeyStorage() {
  const storePath = tmpFile('store.json');
  const store = new FileSignalStore(storePath);

  const identity = await KeyHelper.generateIdentityKeyPair();
  const signedPreKey = await KeyHelper.generateSignedPreKey(identity, 1);

  await store.storeSignedPreKeyWithSignature(1, signedPreKey.keyPair, signedPreKey.signature);

  const loaded = await store.loadSignedPreKey(1);
  const signatureB64 = store.getSignedPreKeySignature(1);
  assert.ok(loaded, '签名预键应已保存');
  assert.ok(signatureB64, '签名应已保存');
  assert.strictEqual(
    Buffer.from(loaded!.pubKey as ArrayBuffer).toString('base64'),
    Buffer.from(signedPreKey.keyPair.pubKey as ArrayBuffer).toString('base64'),
    '加载的签名预键公钥应匹配',
  );
  assert.strictEqual(
    signatureB64,
    Buffer.from(signedPreKey.signature as ArrayBuffer).toString('base64'),
    '存储的签名应匹配原始值',
  );
}

export async function run() {
  await testEnsureLocalIdentityPersists();
  console.log('✔ receiver ensureLocalIdentity 持久化测试通过');

  await testSignedPreKeyStorage();
  console.log('✔ receiver 签名预键存储测试通过');
}

if (require.main === module) {
  run().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
