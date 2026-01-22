# API 文档（项目全量）

基础 URL：`http://127.0.0.1:3000`

> 设计原则：服务器只存储和搬运，不做任何加解密，仅校验签名预键签名；所有密钥/密文均为 base64 字符串。

## 通用约定
- `user_id`：用户标识，区分大小写，建议只用字母/数字/短横线；服务端不校验唯一性。
- `base64`：标准 base64 编码字符串；服务端仅对 `identity_key` 与 `signed_prekey` 相关字段解码验签。
- 时间字段：`created_at`、`ttl_seconds` 以秒为单位（Unix seconds / TTL seconds）。
- 预键字段：`prekeys[].created_at` 与 `prekeys[].ttl_seconds` 用于服务端过期回收。
- `msg_type`：libsignal 消息类型，常见值为 `3`（PreKeyWhisper）、`1/2`（Whisper）。
- 错误响应：JSON 解析失败、签名预键验签失败或字段类型不匹配时返回 `400 Bad Request`；`/bundle/{user}` 若用户未注册返回 `404 Not Found`。

## HTTP API（Rust 中继）

### 1. 注册身份与签名预键
`POST /register`

请求体：
```json
{
  "user_id": "alice",
  "registration_id": 1234,
  "identity_key": "BASE64",
  "signed_prekey": {
    "key_id": 1,
    "public_key": "BASE64",
    "signature": "BASE64"
  },
  "prekeys": [
    { "key_id": 10, "public_key": "BASE64" }
  ]
}
```

字段说明：
- `user_id`：用户标识；同名会覆盖旧身份与签名预键。
- `registration_id`：libsignal 注册 ID（u32）。
- `identity_key`：身份公钥（base64）。
- `signed_prekey.key_id`：签名预键 ID（u32）。
- `signed_prekey.public_key`：签名预键公钥（base64）。
- `signed_prekey.signature`：签名预键签名（base64，由 `identity_key` 对 `signed_prekey.public_key` 签名）。
- `prekeys`：一次性预键列表；如提供，服务端会覆盖已有队列。
- `prekeys[].key_id`：一次性预键 ID（u32）。
- `prekeys[].public_key`：一次性预键公钥（base64）。
- `prekeys[].created_at`：一次性预键创建时间（秒）；可选，默认使用服务端接收时间。
- `prekeys[].ttl_seconds`：一次性预键 TTL（秒）；可选，默认 `PREKEY_TTL_SECONDS` 或 7 天。

关联字段：
- `signed_prekey.signature` 必须与 `identity_key` 对应，否则服务端会返回 `400`。
- `prekeys` 与 `/bundle/{user}`、`/prekeys/{user}/one` 的弹出逻辑关联。

响应：`204 No Content`

### 2. 批量上传一次性预键
`POST /prekeys/upload`

请求体：
```json
{
  "user_id": "alice",
  "prekeys": [
    { "key_id": 10, "public_key": "BASE64" },
    { "key_id": 11, "public_key": "BASE64" }
  ]
}
```

字段说明：
- `user_id`：用户标识；若该用户尚未注册身份，预键仍会被缓存，但 `/bundle/{user}` 仍返回 404。
- `prekeys`：一次性预键列表；该接口为追加行为，不会覆盖既有队列。
- `prekeys[].created_at`：一次性预键创建时间（秒）；可选。
- `prekeys[].ttl_seconds`：一次性预键 TTL（秒）；可选。

行为：
- 服务端会在上传、弹出或打包预键时清理过期预键。

响应：`204 No Content`

### 3. 获取预键包（弹出一个一次性预键）
`GET /bundle/{user}`

响应：
```json
{
  "registration_id": 1234,
  "identity_key": "BASE64",
  "signed_prekey": {
    "key_id": 1,
    "public_key": "BASE64",
    "signature": "BASE64"
  },
  "prekey": { "key_id": 10, "public_key": "BASE64", "created_at": 1736860800, "ttl_seconds": 604800 }
}
```

字段说明：
- `registration_id`：注册 ID。
- `identity_key`：身份公钥。
- `signed_prekey`：签名预键信息。
- `prekey`：一次性预键；若队列耗尽或已过期则为 `null`。

关联字段：
- `prekey` 每次调用都会弹出一条，属于一次性消耗。

错误：`404 Not Found`（用户未注册身份）

### 4. 弹出一个一次性预键（向后兼容）
`GET /prekeys/{user}/one`

响应：
```json
{ "prekey": { "key_id": 10, "public_key": "BASE64", "created_at": 1736860800, "ttl_seconds": 604800 } }
```

字段说明：
- `prekey`：一次性预键；若队列耗尽则为 `null`。

### 5. 投递密文
`POST /message`

请求体：
```json
{
  "id": "uuid-or-client-id",
  "from": "alice",
  "to": "bob",
  "body_b64": "BASE64_CIPHERTEXT",
  "msg_type": 3,
  "registration_id": 1234,
  "ttl_seconds": 2592000,
  "created_at": 1736860800
}
```

MessageEnvelope 字段说明：
- `id`：客户端生成的消息 ID；服务端不保证唯一性。
- `from`：发送方 `user_id`。
- `to`：接收方 `user_id`。
- `body_b64`：密文字节的 base64 编码（不解析）。
- `msg_type`：消息类型（推荐必填），一般为 `3/1/2`。
- `registration_id`：发送方注册 ID（可选，供客户端追溯）。
- `ttl_seconds`：过期时间（秒，可选）；若未提供则不会过期。
- `created_at`：消息创建时间（秒，可选）；若未提供，`ttl_seconds` 的判断以“拉取时刻”为基准。

行为：
- 统一入队（读后即删）；不解析密文。
- 同时向在线用户的 SSE 连接发送轻量通知 `{ "kind": "NEW_MSG" }`。

响应：`202 Accepted`

### 6. 拉取离线密文（读后即删）
`GET /messages/{user}`

响应：
```json
[
  {
    "id": "uuid",
    "from": "alice",
    "to": "bob",
    "body_b64": "BASE64",
    "msg_type": 3,
    "registration_id": 1234,
    "ttl_seconds": 2592000,
    "created_at": 1736860800
  }
]
```

行为：
- 拉取即删除。
- 若 `ttl_seconds` 已过期则丢弃该消息。

### 7. 在线推送（SSE）
`GET /events/{user}`

行为：
- 建立 SSE 连接。
- 当有新密文入队且用户在线时，推送轻量通知：
```json
{ "kind": "NEW_MSG" }
```
客户端收到后应调用 `/messages/{user}` 拉取增量密文并解密。

---

## 客户端与工具（Node/TS）

### 1. 发送端脚本
入口：`src/sender.ts`  
命令：`pnpm sender "<plaintext>"`

环境变量：
- `SERVER_URL`：中继地址，默认 `http://127.0.0.1:3000`。
- `SENDER_ID`：发送方 `user_id`，默认 `alice`。
- `RECEIVER_ID`：接收方 `user_id`，默认 `bob`。
- `SIGNAL_STORE_PATH`：本地持久化存储路径（JSON）。
- `SENDER_AGENT_PORT`：`--serve` 模式的本地代理端口。

行为与关联字段：
- 启动时确保本地身份存在（不重复生成）。
- 调用 `/bundle/{user}` 拉取预键包；`prekey` 为空时会报错。
- 生成 `msg_type` 与 `body_b64` 并调用 `/message` 投递。

### 2. 接收端脚本
入口：`src/receiver.ts`  
命令：`pnpm receiver`

环境变量：
- `SERVER_URL`：中继地址。
- `RECEIVER_ID`：接收方 `user_id`。
- `SENDER_ID`：默认发送方标识（用于构造地址）。
- `SIGNAL_STORE_PATH`：本地持久化存储路径（JSON）。
- `PREKEY_TTL_SECONDS`：一次性预键 TTL（秒）。
- `SIGNED_PREKEY_TTL_SECONDS`：签名预键 TTL（秒）。
- `PREKEY_BATCH_SIZE`：批量生成预键数量。
- `PREKEY_MIN_AVAILABLE`：本地预键低水位阈值。
- `PREKEY_REFRESH_INTERVAL_SECONDS`：后台刷新检查间隔。
- `RECEIVER_AGENT_PORT`：`--serve` 模式的本地代理端口。

行为与关联字段：
- 启动时注册身份与预键（`/register`），并本地持久化签名预键签名。
- 先调用 `/messages/{user}` 拉取离线密文，再订阅 `/events/{user}`。
- 若服务端未返回 `msg_type`，客户端默认按 `3` 处理。
- 定时检查预键数量与 TTL，不足时调用 `/prekeys/upload` 自动补充。

### 3. 时间戳工具
入口：`src/timestampCiphertext.ts`  
命令：`pnpm timestamp "<ciphertext>" [hex|base64|utf8] [outputPath]`

字段说明与范围：
- `ciphertext`：密文本体（字符串）。
- `encoding`：可选 `hex|base64|utf8`，默认 `utf8`（不再自动猜测）。
- `OTS_SALT`：环境变量，可选，`hex` 或 `base64`；未提供时生成 16 字节随机盐。
- `outputPath`：可选，输出 `.ots` 凭证路径。

输出：
- `<outputPath>.ots`：OpenTimestamps 凭证（二进制）。
- `<outputPath>.json`：元数据：
  - `saltHex`：盐（hex）。
  - `saltedHashHex`：`sha256(salt || ciphertext)`（hex）。
  - `ciphertextEncoding`：输入编码。
  - `receiptFile`：凭证文件名。

### 4. 校验工具
入口：`src/validator.ts`（库函数）

MessageAttestationBundle 字段说明：
- `plaintextHashHex`：明文哈希（hex），用于对比解密结果。
- `ciphertextBase64`：密文（base64）。
- `ciphertextHashHex`：`sha256(ciphertext)`（hex）。
- `saltHex`：上链盐（hex，偶数长度）。
- `saltedCiphertextHashHex`：`sha256(salt || ciphertext)`（hex）。
- `otsReceiptBase64`：OpenTimestamps 凭证（base64）。
- `senderId`/`receiverId`/`createdAtMs` 等：可选元数据。

函数：
- `hashPlaintext(plaintext)`：返回明文 `sha256`（hex）。
- `hashCiphertextBase64(ciphertextBase64)`：返回密文 `sha256`（hex）。
- `hashSaltedCiphertext(ciphertextBase64, saltHex)`：返回 `sha256(salt || ciphertext)`（hex）。
- `verifyMessageAttestation(bundle, options)`：
  - `options.plaintext`：可选；未提供时 `plaintextHashOk=false`。
  - `options.ciphertextBase64`：可覆盖 bundle 内密文。
  - `options.timeoutMs`：OTS 验证超时，默认 5000ms。
  - `options.ignoreBitcoinNode`：默认 `true`。
  - 返回 `VerifyResult`：`plaintextHashOk`/`ciphertextHashOk`/`saltedHashOk`/`otsVerified`。

异常与范围：
- `ciphertextBase64`、`saltHex` 需要合法编码；否则 hash 结果可能不可预期（Node 会容忍非法字符）。
- OTS 验证依赖网络环境，失败时 `otsVerified=false`。

---

### 备注
- 服务端仅校验签名预键签名，其他签名/密文内容由客户端负责安全性与一致性校验。
- 若需持久化或分布式扩展，可在不改变接口的情况下替换存储层（Redis/DB/对象存储）。
