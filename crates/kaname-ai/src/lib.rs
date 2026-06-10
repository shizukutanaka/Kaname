//! kaname-ai — Dual-LLM 型安全 AI 層。
//!
//! プロダクトの単一最重要モジュール。
//! Superhuman CVE のような攻撃が型レベルで不可能。
//!
//! # アーキテクチャ
//!
//! - [`dual_llm`]: Phantom Type による型レベル AI 境界 (公開 API)
//! - [`threat_intel`]: AI フィッシング検出、DLP 連携
//! - [`subprocess`]: P-LLM / Q-LLM のプロセス分離 (seccomp / sandbox-exec)
//! - [`llm_bridge`]: ローカル LLM (Phi-4-mini) 統合
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

/// Phantom Type による型レベル AI 境界 (公開 API)。
pub mod dual_llm;
/// Tiered-Risk アクセス制御 (arxiv 2505.22852 §3)。
pub mod tiered_risk;
/// Rule-of-Two: 単一 LLM 出力を盲信しない多数決機構。
pub mod rule_of_two;
/// AI フィッシング検出・コンタクトインテリジェンス・DLP 連携。
pub mod threat_intel;

/// P-LLM / Q-LLM のプロセス分離 (seccomp / sandbox-exec / Job Object)。
/// Dual-LLM 境界 (dual_llm) を迂回した直接利用は禁止 (CLAUDE.md I1-I4)。
pub mod subprocess;
/// ローカル LLM (Phi-4-mini) 統合。現状はスタブ実装 (docs/maturity.md 参照)。
pub mod llm_bridge;

/// 入力プリフライト検査 (kaname-screen PromptScreener のラッパー)。
pub mod preflight;
pub use preflight::{preflight_untrusted, PreflightResult, Finding};

// 公開 API は dual_llm に集約
pub use dual_llm::{
    Content, Trusted, Untrusted, Provenance,
    AnalysisReport, Verdict, LanguageCode, ActionType, TopicTag, BoundedString,
    Bridge, BridgePolicy, BridgeError,
    QuarantinedLlm, PrivilegedLlm, AiError,
};
