//! JMAP モックサーバー実行可能ファイル。
//!
//! 起動: cargo run -p kaname-mockserver --bin jmap-mock
//! デフォルト: http://127.0.0.1:8080
//!
//! 環境変数:
//!   KANAME_MOCK_PORT  ポート番号 (デフォルト: 8080)
//!   KANAME_MOCK_HOST  バインドホスト (デフォルト: 127.0.0.1)

#![deny(unsafe_code)]

use std::sync::Arc;
use std::net::SocketAddr;
use axum::{
    Router,
    routing::{get, post},
    extract::State,
    response::Json,
    http::StatusCode,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

use kaname_mockserver::{MockServer, JmapRequest};

type SharedServer = Arc<MockServer>;

#[tokio::main]
async fn main() {
    // ロガー初期化
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("kaname_mockserver=info,tower_http=info"))
        )
        .init();

    let port: u16 = std::env::var("KANAME_MOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let host = std::env::var("KANAME_MOCK_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let server = Arc::new(MockServer::new());
    let initial_count = server.email_count();

    info!(
        "Kaname Mock Server v{} starting",
        env!("CARGO_PKG_VERSION")
    );
    info!("Loaded {initial_count} fixture emails");

    // ルーター
    let app = Router::new()
        .route("/jmap",         post(handle_jmap))
        .route("/health",       get(health))
        .route("/.well-known/jmap", get(session))
        .with_state(server)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // バインド
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {addr}: {e}");
            std::process::exit(1);
        }
    };

    info!("Listening on http://{addr}");
    info!("  POST /jmap         — JMAP リクエスト処理");
    info!("  GET  /health       — ヘルスチェック");
    info!("  GET  /.well-known/jmap — セッションエンドポイント");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {e}");
        std::process::exit(1);
    }
}

async fn handle_jmap(
    State(server): State<SharedServer>,
    Json(req): Json<JmapRequest>,
) -> Json<serde_json::Value> {
    let resp = server.handle(req);
    Json(serde_json::to_value(resp).unwrap_or(serde_json::Value::Null))
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "service": "kaname-mockserver",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

async fn session(State(server): State<SharedServer>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "capabilities": {
            "urn:ietf:params:jmap:core": {
                "maxSizeUpload": 50_000_000,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": 10_000_000,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": 16,
                "maxObjectsInGet": 500,
                "maxObjectsInSet": 500,
                "collationAlgorithms": ["i;ascii-numeric", "i;ascii-casemap"]
            },
            "urn:ietf:params:jmap:mail": {}
        },
        "accounts": {
            "mock-account-1": {
                "name": "Mock Account",
                "isPersonal": true,
                "isReadOnly": false,
            }
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:mail": "mock-account-1",
        },
        "username": "test@kaname.app",
        "apiUrl": "/jmap",
        "downloadUrl": "/download/{accountId}/{blobId}",
        "uploadUrl": "/upload/{accountId}",
        "eventSourceUrl": "/eventsource/{accountId}",
        "state": server.email_count().to_string(),
    }))
}
