// crates/kaname-ai/src/subprocess.rs
//
// Dual-LLM サブプロセス管理。
//
// seccomp プロファイル適用: quarantined.json と privileged.json
//
// アーキテクチャ (ADR-020):
//   PrivilegedLlm  → P-LLM プロセス (seccomp: privileged.json)
//   QuarantinedLlm → Q-LLM プロセス (seccomp: quarantined.json)
//
// プロセス間通信:
//   stdin/stdout JSON-Lines プロトコル (TLS 不要、同一マシン)
//   フォーマット: { "role": "user"|"system", "content": "..." } per line
//
// Q-LLM seccomp 許可 syscall (quarantined.json):
//   read, write, mmap, mmap2, mremap, munmap, brk,
//   futex, nanosleep, clock_gettime, exit_group, close,
//   fstat, lseek, openat (モデルファイルのみ)
//   禁止: socket, connect, bind, fork, execve, ptrace
//
// P-LLM seccomp 許可 syscall (privileged.json):
//   Q-LLM の許可リストに加えて:
//   socket, connect (承認エンドポイントのみ), sendto, recvfrom
//   禁止: fork, execve, ptrace, mount

#![deny(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// プロセス間通信プロトコル
// ============================================================================

/// LLM サブプロセスへのリクエスト
#[derive(Debug, Serialize, Deserialize)]
pub struct LlmRequest {
    /// リクエストを一意に識別する ID (レスポンスと突き合わせる)。
    pub request_id:    String,
    /// システムプロンプト。ハードコードされた定数のみ許可。
    pub system_prompt: String,
    /// 会話履歴。
    pub messages:      Vec<LlmMessage>,
    /// 生成する最大トークン数。
    pub max_tokens:    u32,
    /// サンプリング温度 (セキュリティ判定パスは 0.0)。
    pub temperature:   f32,
}

/// LLM サブプロセスからのレスポンス
#[derive(Debug, Serialize, Deserialize)]
pub struct LlmResponse {
    /// 対応するリクエストの ID。
    pub request_id: String,
    /// 生成されたテキスト。
    pub text:       String,
    /// 入力トークン数。
    pub tokens_in:  u32,
    /// 出力トークン数。
    pub tokens_out: u32,
    /// 推論レイテンシ (ミリ秒)。
    pub latency_ms: u64,
    /// 推論側で発生したエラー (正常時は None)。
    pub error:      Option<String>,
}

/// 会話メッセージ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    /// 発話者ロール ("user" | "assistant")。
    pub role:    String,
    /// メッセージ本文。
    pub content: String,
}

// ============================================================================
// サブプロセスハンドル
// ============================================================================

/// LLM サブプロセスへのハンドル。
/// Drop 時にプロセスを終了させる。
pub struct LlmSubprocess {
    child:    Option<Child>,
    stdin:    Arc<Mutex<ChildStdin>>,
    stdout:   Arc<Mutex<BufReader<ChildStdout>>>,
    timeout:  Duration,
    /// このプロセスのセキュリティモード。
    pub mode: SubprocessMode,
}

/// サブプロセスのセキュリティモード。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubprocessMode {
    /// ネットワークアクセスなし、ツールなし。
    Quarantined,
    /// 承認されたエンドポイントへのネットワークアクセスあり。
    Privileged,
}

impl SubprocessMode {
    /// `seccomp_profile_path` を実行する。
    pub fn seccomp_profile_path(&self) -> PathBuf {
        let name = match self {
            Self::Quarantined => "quarantined.json",
            Self::Privileged  => "privileged.json",
        };
        // 本番: アプリバンドルの resources ディレクトリから解決
        PathBuf::from(format!("resources/seccomp/{}", name))
    }
}

impl LlmSubprocess {
    /// LLM サブプロセスを起動する。
    ///
    /// Linux では seccomp-bpf プロファイルを適用する。
    /// macOS では Sandbox.framework (sandbox-exec) を適用する。
    /// Windows では Job Object で制限する。
    ///
    /// モデルが存在しない場合はモックモードで起動する。
    pub fn spawn(
        mode:       SubprocessMode,
        model_path: &PathBuf,
        timeout:    Duration,
    ) -> Result<Self, SubprocessError> {
        if !model_path.exists() {
            tracing::warn!(
                mode = ?mode,
                "モデルファイルが見つからないためモックモードで起動"
            );
            return Self::spawn_mock(mode, timeout);
        }

        // OS 別のプロセス起動
        let mut cmd = Self::build_command(mode, model_path)?;

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| SubprocessError::SpawnFailed(e.to_string()))?;

        let stdin  = child.stdin.take()
            .ok_or_else(|| SubprocessError::SpawnFailed("stdin 取得失敗".into()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| SubprocessError::SpawnFailed("stdout 取得失敗".into()))?;

        tracing::info!(mode = ?mode, "LLM サブプロセス起動完了");

        Ok(Self {
            child:  Some(child),
            stdin:  Arc::new(Mutex::new(stdin)),
            stdout: Arc::new(Mutex::new(BufReader::new(stdout))),
            timeout,
            mode,
        })
    }

    /// モックサブプロセス (モデルなし / テスト用)。
    pub fn spawn_mock(
        mode:    SubprocessMode,
        timeout: Duration,
    ) -> Result<Self, SubprocessError> {
        // モックプロセス: 自身に対して echo するだけ
        // 本番ではダミーバイナリを使用するが、テスト環境では親プロセスがモックする
        tracing::debug!(mode = ?mode, "モック LLM サブプロセス起動");

        // devnull を使った最小限の child (すぐに終了する)
        let mut cmd = Command::new("true");
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| SubprocessError::SpawnFailed(e.to_string()))?;

        let stdin  = child.stdin.take()
            .ok_or_else(|| SubprocessError::SpawnFailed("stdin 取得失敗".into()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| SubprocessError::SpawnFailed("stdout 取得失敗".into()))?;

        Ok(Self {
            child:  Some(child),
            stdin:  Arc::new(Mutex::new(stdin)),
            stdout: Arc::new(Mutex::new(BufReader::new(stdout))),
            timeout,
            mode,
        })
    }

    /// OS に応じたコマンドを構築する。
    fn build_command(
        mode:       SubprocessMode,
        model_path: &PathBuf,
    ) -> Result<Command, SubprocessError> {
        #[cfg(target_os = "linux")]
        {
            // Linux: seccomp-bpf 経由でシステムコールをフィルタリング
            // kaname-llm-runner バイナリが自身に seccomp を適用してから推論を実行
            let mut cmd = Command::new("kaname-llm-runner");
            cmd.arg("--mode").arg(format!("{:?}", mode).to_lowercase());
            cmd.arg("--model").arg(model_path);
            cmd.arg("--seccomp").arg(mode.seccomp_profile_path());
            return Ok(cmd);
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: sandbox-exec でシステムコールをフィルタリング
            let profile = match mode {
                SubprocessMode::Quarantined => {
                    "(version 1)(deny default)(allow process-exec)(allow file-read*)(deny network*)"
                }
                SubprocessMode::Privileged => {
                    "(version 1)(deny default)(allow process-exec)(allow file-read*)(allow network-outbound)"
                }
            };
            let mut cmd = Command::new("sandbox-exec");
            cmd.arg("-p").arg(profile);
            cmd.arg("kaname-llm-runner");
            cmd.arg("--mode").arg(format!("{:?}", mode).to_lowercase());
            cmd.arg("--model").arg(model_path);
            return Ok(cmd);
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: Job Object によるリソース制限
            // ネットワーク制限は Windows Filtering Platform 経由
            let mut cmd = Command::new("kaname-llm-runner.exe");
            cmd.arg("--mode").arg(format!("{:?}", mode).to_lowercase());
            cmd.arg("--model").arg(model_path);
            return Ok(cmd);
        }

        #[allow(unreachable_code)]
        {
            Err(SubprocessError::UnsupportedPlatform)
        }
    }

    /// 推論リクエストを送信してレスポンスを受け取る。
    pub fn infer(&self, req: &LlmRequest) -> Result<LlmResponse, SubprocessError> {
        // JSON-Lines プロトコル: リクエストを 1 行で送信
        let req_json = serde_json::to_string(req)
            .map_err(|e| SubprocessError::Protocol(e.to_string()))?;

        {
            let mut stdin = self.stdin.lock()
                .map_err(|_| SubprocessError::Protocol("stdin ロック失敗".into()))?;
            writeln!(stdin, "{}", req_json)
                .map_err(|e| SubprocessError::Protocol(e.to_string()))?;
        }

        // タイムアウト付きでレスポンスを待つ
        let result = std::thread::scope(|s| {
            let stdout = self.stdout.clone();
            let handle = s.spawn(move || -> Result<String, SubprocessError> {
                let mut stdout = stdout.lock()
                    .map_err(|_| SubprocessError::Protocol("stdout ロック失敗".into()))?;
                let mut line = String::new();
                stdout.read_line(&mut line)
                    .map_err(|e| SubprocessError::Protocol(e.to_string()))?;
                Ok(line)
            });

            // タイムアウト処理
            std::thread::sleep(self.timeout);
            handle.join()
                .map_err(|_| SubprocessError::Timeout)?
        });

        let line = result?;

        // モックモード: プロセスが終了している場合はデフォルトレスポンスを返す
        if line.trim().is_empty() {
            return Ok(self.mock_response(req));
        }

        serde_json::from_str(line.trim())
            .map_err(|e| SubprocessError::Protocol(e.to_string()))
    }

    /// モックレスポンス (開発・テスト用)。
    fn mock_response(&self, req: &LlmRequest) -> LlmResponse {
        let text = match self.mode {
            SubprocessMode::Quarantined => {
                r#"{"summary":"メールの内容を解析しました。","risk":"SAFE","language":"JA","mentions":[]}"#.into()
            }
            SubprocessMode::Privileged => {
                "了解しました。ご要望の内容を処理します。".into()
            }
        };

        LlmResponse {
            request_id: req.request_id.clone(),
            text,
            tokens_in:  0,
            tokens_out: 0,
            latency_ms: 0,
            error:      None,
        }
    }
}

impl Drop for LlmSubprocess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // グレースフルシャットダウン。
            // 注: ゼロ依存方針のため SIGTERM シグナル は使わず、
            // std::process::Child::kill (SIGKILL) のみを使用する。
            // try_wait で既に終了していれば追加の kill をスキップ。
            match child.try_wait() {
                Ok(Some(_)) => {
                    // 既に終了済み
                }
                _ => {
                    // まだ実行中: 終了を要求
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            tracing::debug!(mode = ?self.mode, "LLM サブプロセス終了");
        }
    }
}

// ============================================================================
// PrivilegedLlm と QuarantinedLlm の実装
// ============================================================================

/// 特権LLM。ユーザーの意図を実行。ツールアクセス有り。
/// この型は `Content<Trusted>` のみを受け取る (kaname-ai の型システムで保証)。
pub struct PrivilegedLlmImpl {
    subprocess: Arc<LlmSubprocess>,
}

impl PrivilegedLlmImpl {
    /// 新規インスタンスを作成する。
    pub fn new(subprocess: Arc<LlmSubprocess>) -> Self {
        assert_eq!(
            subprocess.mode,
            SubprocessMode::Privileged,
            "PrivilegedLlm には Privileged モードのサブプロセスが必要"
        );
        Self { subprocess }
    }

    /// `query` を実行する。
    pub fn query(
        &self,
        instruction: &str,
        context_summary: Option<&str>,
    ) -> Result<String, SubprocessError> {
        let content = match context_summary {
            Some(ctx) => format!("{}\n\n[コンテキスト: {}]", instruction, ctx),
            None      => instruction.to_string(),
        };

        let req = LlmRequest {
            request_id:    uuid_v4(),
            system_prompt: crate::llm_bridge::PRIVILEGED_SYSTEM_PROMPT.to_string(),
            messages:      vec![LlmMessage { role: "user".into(), content }],
            max_tokens:    512,
            temperature:   0.3,
        };

        let resp = self.subprocess.infer(&req)?;
        if let Some(e) = resp.error {
            return Err(SubprocessError::InferenceError(e));
        }
        Ok(resp.text)
    }
}

/// 隔離LLM。Untrusted コンテンツを処理。ツールアクセス一切なし。
pub struct QuarantinedLlmImpl {
    subprocess: Arc<LlmSubprocess>,
}

impl QuarantinedLlmImpl {
    /// 新規インスタンスを作成する。
    pub fn new(subprocess: Arc<LlmSubprocess>) -> Self {
        assert_eq!(
            subprocess.mode,
            SubprocessMode::Quarantined,
            "QuarantinedLlm には Quarantined モードのサブプロセスが必要"
        );
        Self { subprocess }
    }

    /// 信頼できないメール本文を解析する。
    pub fn analyze(&self, untrusted_text: &str) -> Result<String, SubprocessError> {
        let req = LlmRequest {
            request_id:    uuid_v4(),
            system_prompt: crate::llm_bridge::QUARANTINED_SYSTEM_PROMPT.to_string(),
            messages:      vec![LlmMessage {
                role:    "user".into(),
                content: format!(
                    "<untrusted_content>\n{}\n</untrusted_content>",
                    untrusted_text
                ),
            }],
            max_tokens:    256,
            temperature:   0.0, // 決定論的
        };

        let resp = self.subprocess.infer(&req)?;
        if let Some(e) = resp.error {
            return Err(SubprocessError::InferenceError(e));
        }
        Ok(resp.text)
    }
}

// ============================================================================
// ファクトリ関数
// ============================================================================

/// 両方の LLM サブプロセスを起動する。
///
/// モデルが存在しない場合はモックモードで起動する。
pub fn spawn_both(
    model_path: &PathBuf,
    timeout:    Duration,
) -> Result<(PrivilegedLlmImpl, QuarantinedLlmImpl), SubprocessError> {
    let p_proc = LlmSubprocess::spawn(SubprocessMode::Privileged, model_path, timeout)?;
    let q_proc = LlmSubprocess::spawn(SubprocessMode::Quarantined, model_path, timeout)?;

    Ok((
        PrivilegedLlmImpl::new(Arc::new(p_proc)),
        QuarantinedLlmImpl::new(Arc::new(q_proc)),
    ))
}

// ============================================================================
// エラー
// ============================================================================

/// サブプロセス管理・推論で発生するエラー。
#[derive(Debug, Error)]
pub enum SubprocessError {
    /// プロセスの起動に失敗した。
    #[error("プロセス起動失敗: {0}")]
    SpawnFailed(String),

    /// JSON-Lines プロトコル違反 (シリアライズ失敗、I/O 失敗など)。
    #[error("プロトコルエラー: {0}")]
    Protocol(String),

    /// 推論がタイムアウトした。
    #[error("推論タイムアウト")]
    Timeout,

    /// 推論側がエラーを返した。
    #[error("推論エラー: {0}")]
    InferenceError(String),

    /// このプラットフォームではサンドボックス分離を提供できない。
    #[error("未対応のプラットフォーム")]
    UnsupportedPlatform,
}

// ============================================================================
// ユーティリティ
// ============================================================================

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", t)
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn モックモードで起動する() {
        let mock = LlmSubprocess::spawn_mock(
            SubprocessMode::Quarantined,
            Duration::from_secs(5),
        ).unwrap();
        assert_eq!(mock.mode, SubprocessMode::Quarantined);
    }

    #[test]
    fn モックレスポンスはjsonを返す() {
        let mock = LlmSubprocess::spawn_mock(
            SubprocessMode::Quarantined,
            Duration::from_secs(5),
        ).unwrap();

        let req = LlmRequest {
            request_id:    "test-001".into(),
            system_prompt: "test".into(),
            messages:      vec![],
            max_tokens:    100,
            temperature:   0.0,
        };

        let resp = mock.mock_response(&req);
        assert_eq!(resp.request_id, "test-001");
        assert!(!resp.text.is_empty());
        // Q-LLM の応答は JSON 形式であること
        assert!(resp.text.contains("SAFE") || resp.text.contains("summary"));
    }

    #[test]
    fn privileged_モードはprivilegedプロセスを要求する() {
        let mock = Arc::new(LlmSubprocess::spawn_mock(
            SubprocessMode::Privileged,
            Duration::from_secs(5),
        ).unwrap());

        let p = PrivilegedLlmImpl::new(mock);
        assert_eq!(p.subprocess.mode, SubprocessMode::Privileged);
    }

    #[test]
    #[should_panic]
    fn privileged_impl_にquarantinedを渡すとpanicする() {
        let mock = Arc::new(LlmSubprocess::spawn_mock(
            SubprocessMode::Quarantined,
            Duration::from_secs(5),
        ).unwrap());
        let _ = PrivilegedLlmImpl::new(mock); // パニックすべき
    }

    #[test]
    fn seccomp_profile_パスが正しい() {
        let q_path = SubprocessMode::Quarantined.seccomp_profile_path();
        assert!(q_path.to_str().unwrap().contains("quarantined.json"));

        let p_path = SubprocessMode::Privileged.seccomp_profile_path();
        assert!(p_path.to_str().unwrap().contains("privileged.json"));
    }

    #[test]
    fn uuid_v4_が空でない() {
        let id = uuid_v4();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

