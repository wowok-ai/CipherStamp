use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{mpsc, RwLock};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use xeddsa::xed25519::PublicKey as XedPublicKey;
use xeddsa::Verify;
use axum::http::{header, Method};

/// 半可信中继：仅存储与搬运，不做加解密。
#[derive(Clone, Default)]
struct AppState {
    identities: Arc<RwLock<HashMap<String, IdentityRecord>>>,
    prekeys: Arc<RwLock<HashMap<String, VecDeque<OneTimePreKey>>>>,
    queues: Arc<RwLock<HashMap<String, Vec<MessageEnvelope>>>>,
    watchers: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<NotifyEvent>>>>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct IdentityRecord {
    registration_id: u32,
    identity_key: String,    // base64
    signed_prekey: SignedPreKey,
}

#[derive(Clone, Serialize, Deserialize)]
struct SignedPreKey {
    key_id: u32,
    public_key: String, // base64
    signature: String,  // base64
}

#[derive(Clone, Serialize, Deserialize)]
struct OneTimePreKey {
    key_id: u32,
    public_key: String, // base64
    #[serde(default)]
    created_at: Option<u64>, // unix seconds
    #[serde(default)]
    ttl_seconds: Option<u64>, // seconds
}

#[derive(Clone, Serialize, Deserialize)]
struct RegisterRequest {
    user_id: String,
    registration_id: u32,
    identity_key: String,
    signed_prekey: SignedPreKey,
    #[serde(default)]
    prekeys: Vec<OneTimePreKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct UploadPreKeysRequest {
    user_id: String,
    prekeys: Vec<OneTimePreKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PopPreKeyResponse {
    prekey: Option<OneTimePreKey>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MessageEnvelope {
    id: String,
    from: String,
    to: String,
    body_b64: String, // 加密后的密文，不解析
    #[serde(default)]
    msg_type: Option<u8>,
    #[serde(default)]
    registration_id: Option<u32>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    created_at: Option<u64>, // unix seconds
}

#[derive(Clone, Serialize, Deserialize)]
struct NotifyEvent {
    kind: String, // e.g. "NEW_MSG"
}

#[derive(Clone, Serialize, Deserialize)]
struct PreKeyBundleResponse {
    registration_id: u32,
    identity_key: String,
    signed_prekey: SignedPreKey,
    prekey: Option<OneTimePreKey>,
}

const DEFAULT_PREKEY_TTL_SECONDS: u64 = 60 * 60 * 24 * 7;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{self, Body},
        http::{Request, StatusCode},
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rand::{rngs::StdRng, SeedableRng};
    use serde_json::json;
    use tower::ServiceExt;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use xeddsa::xed25519::PrivateKey as XedPrivateKey;
    use xeddsa::Sign;

    #[tokio::test]
    async fn register_bundle_and_message_flow() {
        let app = build_app(AppState::default());

        let identity_secret = StaticSecret::from([7u8; 32]);
        let identity_pub = X25519PublicKey::from(&identity_secret);
        let mut identity_pub_prefixed = Vec::with_capacity(33);
        identity_pub_prefixed.push(5);
        identity_pub_prefixed.extend_from_slice(identity_pub.as_bytes());
        let identity_key_b64 = STANDARD.encode(&identity_pub_prefixed);

        let signed_secret = StaticSecret::from([9u8; 32]);
        let signed_pub = X25519PublicKey::from(&signed_secret);
        let mut signed_pub_prefixed = Vec::with_capacity(33);
        signed_pub_prefixed.push(5);
        signed_pub_prefixed.extend_from_slice(signed_pub.as_bytes());
        let signed_prekey_pub_b64 = STANDARD.encode(&signed_pub_prefixed);

        let identity_priv = XedPrivateKey::from(&identity_secret.to_bytes());
        let signature: [u8; 64] =
            identity_priv.sign(&signed_pub_prefixed, StdRng::from_seed([1u8; 32]));
        let signature_b64 = STANDARD.encode(signature);

        // 注册身份 + 预键
        let register_payload = json!({
            "user_id": "alice",
            "registration_id": 42,
            "identity_key": identity_key_b64,
            "signed_prekey": { "key_id": 1, "public_key": signed_prekey_pub_b64, "signature": signature_b64 },
            "prekeys": [{ "key_id": 10, "public_key": "cHJla2V5" }] // "prekey"
        });

        let res = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // 拉取预键包应成功并弹出一次性预键
        let res = app
            .clone()
            .oneshot(
                Request::get("/bundle/alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let bundle: PreKeyBundleResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(bundle.registration_id, 42);
        assert!(bundle.prekey.is_some(), "预期弹出一个一次性预键");

        // 投递消息
        let message_payload = json!({
            "id": "m1",
            "from": "alice",
            "to": "bob",
            "body_b64": "Y3Q=", // "ct"
            "msg_type": 3,
            "registration_id": 42,
            "created_at": 1_700_000_000u64
        });
        let res = app
            .clone()
            .oneshot(
                Request::post("/message")
                    .header("content-type", "application/json")
                    .body(Body::from(message_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);

        // 拉取消息应读后即删
        let res = app
            .clone()
            .oneshot(
                Request::get("/messages/bob")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let msgs: Vec<MessageEnvelope> =
            serde_json::from_slice(&body::to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, "m1");

        // 再次拉取应为空
        let res = app
            .oneshot(
                Request::get("/messages/bob")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let msgs: Vec<MessageEnvelope> =
            serde_json::from_slice(&body::to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert!(msgs.is_empty());
    }
}

fn build_app(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "http://127.0.0.1:3001".parse().unwrap(),
            "http://127.0.0.1:3002".parse().unwrap(),
            "http://127.0.0.1:3003".parse().unwrap(),
            "http://localhost:3001".parse().unwrap(),
            "http://localhost:3002".parse().unwrap(),
            "http://localhost:3003".parse().unwrap(),
        ]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .route("/register", post(register_identity))
        .route("/prekeys/upload", post(upload_prekeys))
        .route("/prekeys/:user/one", get(pop_prekey))
        .route("/bundle/:user", get(get_prekey_bundle))
        .route("/message", post(push_message))
        .route("/messages/:user", get(fetch_messages))
        .route("/events/:user", get(event_stream))
        .with_state(state)
        .layer(cors)
}

#[tokio::main]
async fn main() {
    let state = AppState::default();
    let app = build_app(state);

    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
    println!("Signal relay server running on http://{addr}");

    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("server error: {err}");
    }
}

/// 注册身份 + 签名预键（长期部分），仅验签签名预键。
async fn register_identity(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> StatusCode {
    if let Err(status) = verify_signed_prekey(&req.identity_key, &req.signed_prekey) {
        return status;
    }

    let mut identities = state.identities.write().await;
    identities.insert(
        req.user_id.clone(),
        IdentityRecord {
            registration_id: req.registration_id,
            identity_key: req.identity_key,
            signed_prekey: req.signed_prekey,
        },
    );
    drop(identities);

    // 覆盖式写入初始一次性预键队列
    if !req.prekeys.is_empty() {
        let now = now_seconds();
        let normalized = normalize_prekeys(req.prekeys, now);
        let mut prekeys = state.prekeys.write().await;
        prekeys.insert(req.user_id, normalized.into_iter().collect::<VecDeque<_>>());
    }

    StatusCode::NO_CONTENT
}

/// 批量上传一次性预键。
async fn upload_prekeys(
    State(state): State<AppState>,
    Json(req): Json<UploadPreKeysRequest>,
) -> StatusCode {
    let now = now_seconds();
    let normalized = normalize_prekeys(req.prekeys, now);
    let mut prekeys = state.prekeys.write().await;
    let entry = prekeys.entry(req.user_id).or_default();
    prune_expired_prekeys(entry, now);
    for k in normalized {
        entry.push_back(k);
    }
    StatusCode::NO_CONTENT
}

/// 弹出一个一次性预键，用于会话初始化；没有则返回 None。
async fn pop_prekey(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Json<PopPreKeyResponse> {
    let mut prekeys = state.prekeys.write().await;
    let prekey = prekeys.get_mut(&user).and_then(|queue| {
        let now = now_seconds();
        prune_expired_prekeys(queue, now);
        queue.pop_front()
    });
    Json(PopPreKeyResponse { prekey })
}

/// 返回预键包（签名预键 + 弹出一个一次性预键）。
async fn get_prekey_bundle(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Result<Json<PreKeyBundleResponse>, StatusCode> {
    let identity = {
        let identities = state.identities.read().await;
        identities.get(&user).cloned()
    };

    let Some(identity) = identity else {
        return Err(StatusCode::NOT_FOUND);
    };

    let mut prekeys = state.prekeys.write().await;
    let prekey = prekeys.get_mut(&user).and_then(|queue| {
        let now = now_seconds();
        prune_expired_prekeys(queue, now);
        queue.pop_front()
    });

    Ok(Json(PreKeyBundleResponse {
        registration_id: identity.registration_id,
        identity_key: identity.identity_key,
        signed_prekey: identity.signed_prekey,
        prekey,
    }))
}

/// 存储或转发密文，不解析。
async fn push_message(
    State(state): State<AppState>,
    Json(msg): Json<MessageEnvelope>,
) -> StatusCode {
    // 统一落队列保证可靠性，再推送轻量通知。
    let mut queues = state.queues.write().await;
    let target = msg.to.clone();
    queues.entry(target.clone()).or_default().push(msg.clone());
    drop(queues);

    let notify = NotifyEvent {
        kind: "NEW_MSG".to_string(),
    };
    let mut watchers = state.watchers.write().await;
    if let Some(chans) = watchers.get_mut(&target) {
        chans.retain(|tx| tx.try_send(notify.clone()).is_ok());
    }
    drop(watchers);

    StatusCode::ACCEPTED
}

/// 读后即删；同时清理过期消息（TTL 秒级）。
async fn fetch_messages(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Json<Vec<MessageEnvelope>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let mut queues = state.queues.write().await;
    let entry = queues.entry(user).or_default();
    let mut drained = Vec::new();

    for msg in entry.drain(..) {
        if let Some(ttl) = msg.ttl_seconds {
            let created = msg.created_at.unwrap_or(now);
            if now.saturating_sub(created) > ttl {
                continue; // 丢弃过期
            }
        }
        drained.push(msg);
    }

    // 读完即删策略
    Json(drained)
}

/// SSE 单向推送：在线直接送达。
async fn event_stream(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let (tx, rx) = mpsc::channel::<NotifyEvent>(16);
    {
        let mut watchers = state.watchers.write().await;
        watchers.entry(user.clone()).or_default().push(tx);
    }

    let stream = ReceiverStream::new(rx).map(|msg| {
        let payload = serde_json::to_string(&msg).unwrap_or_default();
        Ok::<Event, std::convert::Infallible>(Event::default().data(payload))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn prekey_ttl_seconds() -> u64 {
    std::env::var("PREKEY_TTL_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|val| *val > 0)
        .unwrap_or(DEFAULT_PREKEY_TTL_SECONDS)
}

fn normalize_prekeys(mut prekeys: Vec<OneTimePreKey>, now: u64) -> Vec<OneTimePreKey> {
    let ttl = prekey_ttl_seconds();
    for prekey in &mut prekeys {
        if prekey.created_at.is_none() {
            prekey.created_at = Some(now);
        }
        if prekey.ttl_seconds.is_none() {
            prekey.ttl_seconds = Some(ttl);
        }
    }
    prekeys
}

fn prune_expired_prekeys(queue: &mut VecDeque<OneTimePreKey>, now: u64) {
    if queue.is_empty() {
        return;
    }
    let ttl_default = prekey_ttl_seconds();
    let mut retained = VecDeque::with_capacity(queue.len());
    while let Some(mut prekey) = queue.pop_front() {
        if prekey.created_at.is_none() {
            prekey.created_at = Some(now);
        }
        if prekey.ttl_seconds.is_none() {
            prekey.ttl_seconds = Some(ttl_default);
        }
        if !is_prekey_expired(&prekey, now) {
            retained.push_back(prekey);
        }
    }
    *queue = retained;
}

fn is_prekey_expired(prekey: &OneTimePreKey, now: u64) -> bool {
    let created_at = prekey.created_at.unwrap_or(now);
    let ttl = prekey.ttl_seconds.unwrap_or(prekey_ttl_seconds());
    now.saturating_sub(created_at) >= ttl
}

fn verify_signed_prekey(identity_key_b64: &str, signed_prekey: &SignedPreKey) -> Result<(), StatusCode> {
    let identity_key = decode_public_key(identity_key_b64)?;
    let message = decode_message_key(&signed_prekey.public_key)?;
    let signature = decode_signature(&signed_prekey.signature)?;

    let public_key = XedPublicKey(identity_key);
    public_key
        .verify(&message, &signature)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn decode_signature(input: &str) -> Result<[u8; 64], StatusCode> {
    let bytes = STANDARD
        .decode(input)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn decode_public_key(input: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = STANDARD
        .decode(input)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let normalized = if bytes.len() == 33 {
        if bytes[0] != 5 {
            return Err(StatusCode::BAD_REQUEST);
        }
        &bytes[1..]
    } else {
        bytes.as_slice()
    };
    normalized
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn decode_message_key(input: &str) -> Result<Vec<u8>, StatusCode> {
    let bytes = STANDARD
        .decode(input)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() == 33 {
        if bytes[0] != 5 {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
