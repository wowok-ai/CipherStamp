import assert from 'assert';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { mapBundleToDevice, FileSignalStore, ensureLocalIdentity } from '../src/sender';

function tmpFile(name: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wowok-sender-'));
  return path.join(dir, name);
}

async function testMapBundleToDevice() {
  const bundle = {
    registration_id: 1234,
    identity_key: Buffer.from('id-key').toString('base64'),
    signed_prekey: {
      key_id: 9,
      public_key: Buffer.from('spk').toString('base64'),
      signature: Buffer.from('sig').toString('base64'),
    },
    prekey: {
      key_id: 11,
      public_key: Buffer.from('opk').toString('base64'),
    },
  };

  const device = mapBundleToDevice(bundle);
  assert.strictEqual(device.registrationId, 1234);
  assert.strictEqual(Buffer.from(device.identityKey as ArrayBuffer).toString('utf8'), 'id-key');
  assert.strictEqual(device.signedPreKey.keyId, 9);
  assert.strictEqual(Buffer.from(device.signedPreKey.publicKey as ArrayBuffer).toString('utf8'), 'spk');
  assert.strictEqual(Buffer.from(device.signedPreKey.signature as ArrayBuffer).toString('utf8'), 'sig');
  assert.ok(device.preKey, 'preKey 应存在');
  assert.strictEqual(device.preKey?.keyId, 11);
  assert.strictEqual(Buffer.from(device.preKey?.publicKey as ArrayBuffer).toString('utf8'), 'opk');
}

async function testEnsureLocalIdentityPersists() {
  const storePath = tmpFile('store.json');
  const store = new FileSignalStore(storePath);

  await ensureLocalIdentity(store);
  const firstIdentity = await store.getIdentityKeyPair();
  const firstReg = await store.getLocalRegistrationId();
  assert.ok(firstIdentity && firstReg, '首次初始化应生成身份与 registrationId');

  await ensureLocalIdentity(store);
  const secondIdentity = await store.getIdentityKeyPair();
  const secondReg = await store.getLocalRegistrationId();

  assert.strictEqual(firstReg, secondReg, '二次调用不应改变 registrationId');
  assert.strictEqual(
    Buffer.from(firstIdentity!.pubKey as ArrayBuffer).toString('base64'),
    Buffer.from(secondIdentity!.pubKey as ArrayBuffer).toString('base64'),
    '身份公钥应保持一致',
  );
}

export async function run() {
  await testMapBundleToDevice();
  console.log('✔ sender mapBundleToDevice 通过');

  await testEnsureLocalIdentityPersists();
  console.log('✔ sender ensureLocalIdentity 持久化测试通过');
}

if (require.main === module) {
  run().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
