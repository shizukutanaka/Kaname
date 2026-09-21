//! kaname-llm-runner — Dual-LLM 用の推論ワーカープロセス (D2 Phase 3)。
//!
//! `subprocess.rs` が `sandbox-exec` (macOS) / seccomp (Linux) 経由で
//! 起動する分離プロセス本体。stdin に `LlmRequest` の JSON-Lines を
//! 受け取り、stdout に `LlmResponse` の JSON-Lines を返す。
//!
//! 起動引数: `--mode quarantined|privileged --model <path> [--seccomp <path>]`
//! (`--seccomp` は Linux 側で seccomp-bpf を適用するためのプロファイル
//! パス — 本バイナリ自身は適用処理を持たず、親がサンドボックスを施す。
//! 引数として受け取るのは将来の自己適用実装との互換のため)。
//!
//! モデルロードに失敗した場合は stderr に理由を出して即終了する —
//! 呼び出し側は stdout EOF (空行) をプロセス死亡として検出する。

#![deny(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kaname_ai::llm_bridge::{InferenceRequest, LocalLlmRunner, ModelConfig, Role, Turn};
use kaname_ai::subprocess::{LlmRequest, LlmResponse};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let Some(model_path) = get("--model").map(PathBuf::from) else {
        eprintln!("usage: kaname-llm-runner --mode <quarantined|privileged> --model <path>");
        return ExitCode::from(2);
    };
    let mode = get("--mode").unwrap_or_else(|| "quarantined".into());
    // D128: --seccomp 引数は受理するが、seccomp の適用は現状どこにも
    // 実装されていない (親側は渡すだけ、ここも読み捨てるだけだった —
    // 「適用は親側の責務」というコメントは相互に無責任なすれ違いだった)。
    // Linux 側は実装が揃うまで build_command が SandboxUnavailable で
    // フェイルクローズするため、この引数が届くことはない。
    let _seccomp = get("--seccomp");

    let config = match mode.as_str() {
        "privileged" => ModelConfig::privileged(),
        _ => ModelConfig::quarantined(),
    };
    let config = ModelConfig {
        model_path,
        ..config
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ランタイム初期化失敗: {e}");
            return ExitCode::from(2);
        }
    };

    let runner = match rt.block_on(LocalLlmRunner::load(config)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("モデルロード失敗: {e}");
            return ExitCode::from(2);
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<LlmRequest>(&line) {
            Ok(req) => run_inference(&runner, &req),
            Err(e) => LlmResponse {
                request_id: String::new(),
                text: String::new(),
                tokens_in: 0,
                tokens_out: 0,
                latency_ms: 0,
                error: Some(format!("リクエストのパース失敗: {e}")),
            },
        };
        let Ok(json) = serde_json::to_string(&resp) else {
            continue;
        };
        if writeln!(out, "{json}").is_err() || out.flush().is_err() {
            break; // 親がパイプを閉じた
        }
    }
    ExitCode::SUCCESS
}

fn run_inference(runner: &std::sync::Mutex<LocalLlmRunner>, req: &LlmRequest) -> LlmResponse {
    // 最後の user メッセージがプロンプト本体、それ以前は history
    let mut history: Vec<Turn> = Vec::new();
    let mut user_message = String::new();
    for (i, m) in req.messages.iter().enumerate() {
        let role = match m.role.as_str() {
            "assistant" => Role::Assistant,
            "system" => Role::System,
            _ => Role::User,
        };
        if i == req.messages.len() - 1 && matches!(role, Role::User) {
            user_message = m.content.clone();
        } else {
            history.push(Turn {
                role,
                content: m.content.clone(),
            });
        }
    }

    let infer_req = InferenceRequest {
        system_prompt: req.system_prompt.clone(),
        user_message,
        history,
    };

    let runner = runner.lock().unwrap_or_else(|e| e.into_inner());
    match runner.infer(&infer_req) {
        Ok(r) => LlmResponse {
            request_id: req.request_id.clone(),
            text: r.text,
            tokens_in: r.tokens_in,
            tokens_out: r.tokens_out,
            latency_ms: r.latency_ms,
            error: None,
        },
        Err(e) => LlmResponse {
            request_id: req.request_id.clone(),
            text: String::new(),
            tokens_in: 0,
            tokens_out: 0,
            latency_ms: 0,
            error: Some(format!("{e}")),
        },
    }
}
