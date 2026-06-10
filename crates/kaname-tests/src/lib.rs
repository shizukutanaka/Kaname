//! kaname-tests — 統合テスト・敵対テスト・プロパティテスト・ベンチマーク。
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod adversarial;
#[cfg(test)]
mod agentdojo;
pub mod integration;
pub mod property_tests;
