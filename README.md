# wowok

- 前端脚本：`src/sender.ts` / `src/receiver.ts`（基于 `libsignal-protocol-typescript` 的收发示例；接收端使用 SSE 监听新消息信令，收到后再拉取密文解密，避免丢包）
- 时间戳工具：`src/timestampCiphertext.ts`（对密文加盐哈希并提交到 OpenTimestamps，生成 `.ots` 凭证）
- 验证工具：`src/validator.ts`（串联明文 → 密文 → 加盐哈希 → OTS 证明的完整校验）
- 半可信中继服务（Rust / Axum）：`server/src/main.rs` 只做存储与搬运，仅校验签名预键签名。

## 快速开始

### Node 脚本
```bash
pnpm install --store-dir .pnpm-store
pnpm sender "你好"
pnpm receiver

# 为密文生成 OTS 凭证（可自定义盐）
OTS_SALT="001122..." pnpm timestamp "<ciphertext>" [hex|base64|utf8] [outputPath]
```

### Rust 中继
```bash
cd server
cargo run
```
服务默认监听 `127.0.0.1:3000`，接口详见 `docs/api.md`。消息投递统一入队，在线用户仅收到轻量 `NEW_MSG` 通知（SSE），客户端再按序拉取密文，保证可靠性。

### 启动前端
```bash
pnpm web
```
若要在网页中输入明文并解密显示，请先启动本地代理：
```bash
pnpm sender -- --serve
pnpm receiver -- --serve
pnpm validator
```

## 环境变量
本项目不提供 `.env` 文件，如需覆盖默认值请在终端里设置：
- `SERVER_URL`：中继地址。
- `SENDER_ID` / `RECEIVER_ID`：默认用户标识。
- `PREKEY_TTL_SECONDS` / `SIGNED_PREKEY_TTL_SECONDS`：预键 TTL。
- `PREKEY_BATCH_SIZE` / `PREKEY_MIN_AVAILABLE` / `PREKEY_REFRESH_INTERVAL_SECONDS`：预键刷新策略。
- `SENDER_AGENT_PORT` / `RECEIVER_AGENT_PORT`：本地代理端口。
- `VALIDATOR_URL`：validator 服务地址（默认 `http://127.0.0.1:3103`）。
- `VALIDATOR_AGENT_PORT`：validator 本地端口（默认 3103）。
- `OTS_SALT`：时间戳工具的盐（hex 或 base64）。

## 验证链路
使用 `src/validator.ts` 提供的结构体 `MessageAttestationBundle` 与 `verifyMessageAttestation`：
- 复算明文哈希（可选，需提供明文）
- 复算密文哈希、加盐哈希
- 校验 OTS 凭证（调用 OpenTimestamps.verify）

## 注意
- OTS 加盐：服务器不生成盐，建议客户端本地生成；可通过环境变量 `OTS_SALT` 固定盐，便于复验。
- 中继仅校验签名预键签名，密文视为二进制 Blob；在线优先转发，离线队列读后即删。
- sender/receiver 会调用 OpenTimestamps `stamp` 生成凭证并发送给 validator；网络不佳时会变慢或失败（失败时仅记录警告）。
