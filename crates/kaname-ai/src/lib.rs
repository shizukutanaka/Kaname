//! kaname-ai — Dual-LLM 型安全 AI 層。
//!
//! プロダクトの単一最重要モジュール。
//! Superhuman CVE のような攻撃が型レベルで不可能。
//!
//! # アーキテクチャ
//!
//! - [`dual_llm`]: Phantom Type による型レベル AI 境界 (公開 API)
//! - [`threat_intel`]: AI フィッシング検出、DLP 連携
//! - `subprocess`: P-LLM / Q-LLM のプロセス分離 (内部実装、seccomp)
//! - `llm_bridge`: ローカル LLM (Phi-4-mini) 統合 (内部実装)
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

pub mod dual_llm;
pub mod tiered_risk;
pub mod rule_of_two;
pub mod threat_intel;

// 内部モジュール: 実装詳細を露出しない
mod subprocess;
mod llm_bridge;

// 公開 API は dual_llm に集約
pub use dual_llm::{
    Content, Trusted, Untrusted, Provenance,
    AnalysisReport, Verdict, LanguageCode, ActionType, TopicTag, BoundedString,
    Bridge, BridgePolicy, BridgeError,
    QuarantinedLlm, PrivilegedLlm, AiError,
};
