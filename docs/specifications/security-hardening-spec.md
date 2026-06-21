# セキュリティ強化仕様書

**バージョン**: 1.0  
**作成日**: 2026-06-20  
**対象ブランチ**: `claude/sleepy-keller-1wyggy`  
**コミット数**: 25 件 (本セッション)  
**テスト数**: 865 件 (全 PASS)

---

## 1. 概要

本仕様書は、Kaname の全 20+ クレートに対して実施した **Socratic セキュリティ強化ループ** の成果を記録する。

手法: 各クレートについて「攻撃者が何をするか?」と問いかけ、脆弱性を発見し、修正し、回帰テストを追加し、コミット・プッシュする。全ループで CLAUDE.md の絶対不変条件 (I1〜I6) を維持した。

---

## 2. 発見・修正した脆弱性

### 2.1 カテゴリ別一覧

| # | カテゴリ | 影響クレート | 修正内容 |
|---|---|---|---|
| 1 | **OOM/DoS via 無制限入力** | observability, privacy, jmap, saas-guard, sandbox, bec, mls, screen, memory-guard, dlp, ai, continuity, i18n, render | `MAX_*_BYTES` 上限 + UTF-8 境界切り詰め |
| 2 | **未来タイムスタンプバイパス** | billing, continuity, oobv | `saturating_sub` → `ts > now` の明示チェック |
| 3 | **SQL インジェクション** | store | PRAGMA 値バリデーション + パス SQL エスケープ |
| 4 | **ドメイン混同 via `contains()`** | pivot, screen | `extract_hostname()` + `host_is()` ドット境界照合 |
| 5 | **NaN/Infinity による比較バイパス** | bec, ssa, store, memory-guard | `is_finite()` ガード + 0.0 フォールバック |
| 6 | **シングルクォート img src バイパス** | render | 正規表現を追加しシングルクォートも検出 |
| 7 | **スタックオーバーフロー via 深い再帰** | dlp | `MAX_DEPTH=64` ガード |
| 8 | **空 AND 条件の vacuous truth** | dlp | 空 AND → マッチなし (false) に変更 |
| 9 | **公開鍵長不一致 OOM** | crypto | `validate_length()` で `alg.public_key_len()` を照合 |
| 10 | **カタログ値サイズ無制限** | i18n | キー 256B・値 4KB 上限を追加 |
| 11 | **KeyPackage キャッシュ無制限** | mls | 64KB/件・100件/email 上限 |
| 12 | **エポック検証欠落** | mls | Commit/Application のエポック前進確認 |
| 13 | **制御文字インジェクション** | ai (Bridge) | `source_email_id` の `< 0x20 || 0x7F` チェック |
| 14 | **Webhook ボディ OOM** | billing | 512KB 上限 + 1024B ヘッダー上限 |
| 15 | **email_id 無制限 OOM** | continuity | 512B 上限 |
| 16 | **DLP テキスト 100MB 評価** | dlp | 1MB 切り詰め + キーワード 500 件上限 |
| 17 | **LLM IPC バッファ OOM** | ai | `Content<Untrusted>` を 4MB に制限 |

### 2.2 クレート別コミット

| クレート | コミット | 主な修正 |
|---|---|---|
| kaname-observability | 088b450 | `sanitize()` 64KB 上限 |
| kaname-privacy | 8aa1cdf | ZK 検索クエリ・ID サイズ上限 |
| kaname-store | 708c19f | PRAGMA 注入・パス SQL 注入防止 |
| kaname-jmap | 6a466a0 | ID リスト・件名サイズ上限 |
| kaname-saas-guard | a53aefd | sender 長さ上限 |
| kaname-render | 1173f54 | シングルクォート img src 修正 |
| kaname-bec | c6c187a | Levenshtein OOM・NaN バイパス・トークナイズ OOM |
| kaname-sandbox | 95d0413 | RenderHints clamp + filename 上限 |
| kaname-ssa | 75e8d5a | NaN スタイル特徴量バイパス |
| kaname-pivot | 431aee2 | ドメイン混同修正 |
| kaname-oobv | e982643 | 時刻アンダーフロー安全化 |
| kaname-mls | 281ffc9 | 25MB 上限 + KP キャッシュ上限 |
| kaname-crypto | fa92ede | PublicKey 長さ検証 |
| kaname-billing | 7625715 | 未来タイムスタンプバイパス + ボディ OOM |
| kaname-continuity | 6a753cb | email_id 上限 + 未来時刻バイパス |
| kaname-i18n | 15ad938 | カタログ値サイズ上限 |
| kaname-screen | 9452aaa | screen/audit 入力サイズ上限 |
| kaname-memory-guard | d187f34 | content_hint 8KB 上限 |
| kaname-dlp | 2da21b0 | full_text 1MB 上限 + キーワード 500 件上限 |
| kaname-ai | 92c042b | `Content<Untrusted>` 4MB 上限 |

---

## 3. 長所 (Strengths)

### 3.1 設計レベル

- **Phantom Type による型安全 AI 境界**: `Content<Untrusted>` → `QuarantinedLlm` のみ。コンパイル時に Untrusted の P-LLM への流入を防止 (I1-I4)
- **AnalysisReport の構造化スキーマ**: 自由テキストフィールドなし。プロンプト注入の結果が Q-LLM 出力に残存できない (I2)
- **Bridge の多段検証**: email_id 整合性・score 範囲・攻撃マーカー・OutputAuditor の 5 ステップ
- **ハイブリッド PQC 暗号**: X25519 + ML-KEM-768 の X-Wing 構成。どちらか一方が安全なら全体が安全
- **SQLCipher + ハッシュチェーン台帳**: at-rest 暗号化 + 改ざん検知
- **`#[deny(unsafe_code, unwrap_used, expect_used)]`**: 全クレートで強制。本番コードに unwrap 禁止 (I6)

### 3.2 実装レベル

- **定数時間比較 (`constant_time_eq`)**: HMAC 比較のタイミング攻撃防止
- **X25519 all-zero 検出 (`validate_x25519_output`)**: arxiv 2026/192 V4 対策
- **`saturating_sub` による時刻計算**: オーバーフロー安全 (ただし未来タイムスタンプは別途チェック必要)
- **`DeduplicatorInMem` の容量上限**: Stripe webhook の重複 ID による OOM 防止
- **MAX_DEPTH=64 の条件ツリー制限**: DLP 評価の再帰スタックオーバーフロー防止
- **全角 Unicode・ゼロ幅文字の正規化**: 攻撃マーカー検出の回避防止

### 3.3 テスト品質

- **865 件の自動テスト** (全 PASS)
- **プロパティテスト (proptest)**: `kaname-bec`, `kaname-ssa`, `kaname-continuity`, `kaname-memory-guard`, `kaname-screen`, `kaname-dlp`
- **境界値テスト**: 25MB+1B のペイロード・NaN/Infinity スコア・未来タイムスタンプ・深いネスト

---

## 4. 短所・残存リスク (Weaknesses)

### 4.1 アーキテクチャレベル

| # | 課題 | 影響 | 優先度 |
|---|---|---|---|
| W1 | `QuarantinedLlm::analyze()` がトレイト定義のみでモック実装 | 本番 LLM 統合時の入力サイズ上限が Q-LLM バックエンド依存 | 🔴 HIGH |
| W2 | MLS の `openmls` クレートがスタブ実装 | 実際の RFC 9420 暗号文脈でのエポック検証が未テスト | 🔴 HIGH |
| W3 | `kaname-store` の SQLite ファイルパス生成に `PathBuf::display()` を使用 | Windows の非 UTF-8 パス (稀) で `\u{FFFD}` 置換が発生する可能性 | 🟡 MEDIUM |
| W4 | `kaname-billing` の `DeduplicatorInMem` は in-process | プロセス再起動で dedup 状態消失 → 72h Stripe リプレイウィンドウ中に重複処理の可能性 | 🟡 MEDIUM |
| W5 | `kaname-screen` の `PromptScreener` は静的パターンリスト | 新しいプロンプト注入技法 (多言語混合・Unicode 絵文字埋め込み等) への対応遅延 | 🟡 MEDIUM |
| W6 | `kaname-dlp` の正規表現は `regex` クレートで線形時間保証 | ただし Keyword リーフの `text.to_lowercase()` は全テキスト毎回アロケーション | 🟢 LOW |
| W7 | `kaname-crypto` の `PublicKey::validate_length()` はオプショナル | デシリアライズ後の明示的呼び出しを忘れると未検証鍵がバックエンドに到達 | 🟡 MEDIUM |
| W8 | `kaname-oobv` の `now_unix_secs()` が `unwrap_or(u64::MAX)` | `u64::MAX` で期限切れ扱いは安全だが、時計が壊れた場合の診断性が低い | 🟢 LOW |

### 4.2 テストカバレッジ

| クレート | 残存ギャップ |
|---|---|
| kaname-mls | `openmls` 本番バックエンドとの結合テストなし |
| kaname-sandbox | vsock 経由の実際の VM 通信テストなし |
| kaname-tray | システムトレイ UI のテスト困難 |
| kaname-ui | SolidJS フロントエンドの E2E テストなし |

---

## 5. 改善点と実装計画

### 5.1 即時実装 (本セッション)

以下を本仕様書コミット後に実装する:

#### P1: `PublicKey` デシリアライズ後自動検証 (W7 対策)

`PublicKey<K>` に `#[serde(try_from)]` を使い、デシリアライズ時に長さ検証を自動実行する。

```rust
// 現状: デシリアライズ後に validate_length() を手動呼び出しが必要
// 改善: Deserialize 時に自動検証
impl<'de, K: KeyKind> Deserialize<'de> for PublicKey<K> {
    // try_from で長さ検証を強制
}
```

#### P2: `Keyword` 述語の `to_lowercase()` キャッシュ (W6 対策)

`DlpEngine::evaluate()` で `text.to_lowercase()` を一度だけ計算して再利用。

#### P3: `PromptScreener` へのマルチバイト混合パターン追加 (W5 対策)

絵文字区切り (`i😀g😀n😀o😀r😀e`) や Base64 エンコードされた命令の検出ルールを追加。

#### P4: `validate_length()` の `Serde` 統合 (W7 対策)

デシリアライズ時に長さ不一致を自動でエラーにする実装を `kaname-crypto` に追加。

---

## 6. 修正パターン集 (コーディング標準への追記)

### 6.1 サイズ制限パターン (UTF-8 安全)

```rust
// ✅ 標準パターン: UTF-8 境界での切り詰め
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes { return s; }
    let end = (0..=max_bytes).rev()
        .find(|&i| s.is_char_boundary(i)).unwrap_or(0);
    &s[..end]
}
```

### 6.2 タイムスタンプ比較パターン (未来値防止)

```rust
// ❌ saturating_sub は未来タイムスタンプをバイパスさせる
let age = now.saturating_sub(ts); // ts > now → age = 0 (通過)

// ✅ 未来値を明示的に拒否
if ts > now.saturating_add(TOLERANCE) {
    return Err(Error::FutureTimestamp);
}
let age = now - ts; // ts <= now が保証済み
```

### 6.3 ドメイン照合パターン (混同防止)

```rust
// ❌ contains() はサブドメイン偽装を通す
url.contains("teams.microsoft.com") // evilteams.microsoft.com も通過

// ✅ hostname 抽出 + ドット境界照合
fn host_is(hostname: &str, domain: &str) -> bool {
    hostname == domain || hostname.ends_with(&format!(".{domain}"))
}
let hostname = extract_hostname(url);
host_is(hostname, "teams.microsoft.com")
```

### 6.4 NaN/Infinity 防御パターン

```rust
// ❌ NaN 比較は常に false → 閾値を素通り
if score >= threshold { warn!() } // score=NaN → 警告なし

// ✅ is_finite() で事前ガード
let score = if raw.is_finite() { raw } else { 0.0 };
if score >= threshold { warn!() }
```

---

## 7. STRIDE マッピング (追記)

本セッションで発見した脆弱性を STRIDE に対応させる:

| 脆弱性 | STRIDE | 修正 |
|---|---|---|
| 未来タイムスタンプによる Webhook バイパス | **S** poofing | 明示的未来値チェック |
| `contains()` ドメイン混同 | **S** poofing | `host_is()` 照合 |
| NaN スコアによる BEC/SSA バイパス | **T** ampering | `is_finite()` ガード |
| PRAGMA SQL 注入 | **T** ampering | 入力バリデーション |
| OOM/DoS via 無制限入力 (17 箇所) | **D** enial of Service | サイズ上限 |
| img src シングルクォートバイパス | **E** levation of Privilege | 正規表現追加 |
| 空 AND 条件の vacuous truth | **E** levation of Privilege | false に変更 |
| LLM IPC への 100MB 転送 | **D** enial of Service | 4MB 上限 |

---

## 8. 次のアクション (バックログ)

### Sprint N+1 (優先度順)

1. **`openmls` 実統合**: スタブを実際の `openmls 0.6` クレートに置き換え、RFC 9420 準拠テスト追加 (W2)
2. **Redis dedup**: `DeduplicatorInMem` を Redis SET NX + 72h TTL に置き換え (W4)
3. **`PublicKey` Serde 自動検証**: `#[serde(try_from = "RawPublicKey")]` パターンへ移行 (W7)
4. **E2E テスト**: Playwright で SolidJS UI の主要フロー (受信→BEC 警告→AI 要約) をテスト
5. **MLS 結合テスト**: Docker Compose で 2 ノード MLS 通信テスト

### 将来検討

- **WebAssembly サンドボックス**: Q-LLM を Wasm で実行し seccomp を不要にする
- **形式検証**: `kani` でメモリ安全性の形式証明 (特に kaname-crypto の KEM 実装)
- **ファジング**: `cargo-fuzz` で kaname-billing/kaname-jmap/kaname-dlp のエントリポイントをファジング

---

*本仕様書は `docs/threat-model.md` の補完文書として機能する。新たな攻撃クラスが発見された場合は両文書を同時更新すること。*

---

## 9. Qiita/Zenn 調査由来の追加強化 (v1.1 — 2026-06-21)

国内技術記事 (Qiita / Zenn) で 2025-2026 に報告された新攻撃パターンに基づく追加強化。

### 9.1 発見された新攻撃クラス

| ID | 攻撃名 | 出典 | 概要 |
|---|---|---|---|
| **A1** | Unicode タグ文字注入 | [Qiita: 絵文字や空白に攻撃命令を隠せる](https://qiita.com/sharu389no/items/a94aedbed2cb24edd9b7) | `U+E0000..=U+E007F` の不可視文字に命令を埋め込む (成功率 ~90%) |
| **A2** | ANSI エスケープ隠蔽 | [Qiita: jqwik 事件](https://qiita.com/quotidia/items/8657462d9549c989d075) | OSS 文字列に `\x1b[` を仕込み端末非表示・AI 入力に残す |
| **A3** | ホモグリフ・多言語 | [Zenn: homoglyph プロンプト検証](https://zenn.dev/fmuuly/articles/e8c481bf265007) | Cyrillic/Greek の Latin 類似字で OOV 誘発し検閲突破 |
| **A4** | プロンプトワーム | [Zenn: prompt-worm-quarantine](https://zenn.dev/76hata/articles/prompt-worm-attack-agent-quarantine-design) | エージェント間メッセージに次エージェント向け命令を埋め込み感染拡大 |
| **A5** | 出力インジェクション | [Zenn: Tool Use・MCP 時代の対策](https://zenn.dev/0h_n0/articles/78e4204a2a50c3) | LLM 応答中の Markdown/HTML/画像 URL クエリでデータ流出 |
| **A6** | Quishing (QR Phishing) | [Zenn: Cybozu PSIRT 2025年12月](https://zenn.dev/cybozu_psirt/articles/81a5479a194fb2) | モバイル経由 BEC の主流化 |

### 9.2 適用した改善

| # | 対象 | 改善 | 優先度 | コミット |
|---|---|---|---|---|
| **A1-fix** | `kaname-screen::PromptScreener` | Unicode タグ領域を `extract_unicode_tag_payload()` で復号し `ScreenRisk::UnicodeTagInjection` で Blocked。`is_zero_width_or_format()` にも `U+E0000..=U+E007F` を追加 | P0 | (本コミット) |
| **A1-audit** | `kaname-screen::OutputAuditor` | 出力中のタグ文字も `AuditFinding::UnicodeTagInjection` で検出 | P0 | (本コミット) |
| **A2-fix** | `kaname-screen::OutputAuditor` | `detect_ansi_escape()` で ESC (0x1B) を検出し `AuditFinding::AnsiEscapeSequence` で警告。`\r` 単独は `CarriageReturnOverwrite` で検出 (CRLF は通過) | P0 | (本コミット) |
| **A3-fix** | `kaname-screen::normalize_for_matching` | `homoglyph_to_ascii()` で Cyrillic/Greek の Latin 類似字 39 種を ASCII に折りたたみ。外部依存ゼロ | P1 | (本コミット) |

### 9.3 残課題 (Sprint N+2 候補)

- **A4 対策**: `kaname-ai::tiered_risk` に `Provenance::Agent` を追加し、エージェント間メッセージにも `PromptScreener` を強制適用
- **A5 拡張**: `OutputAuditor` に Markdown 画像 (`![alt](url)`) クエリパラメータ exfil の検出を追加
- **A6 対策**: `kaname-render::quishing` を `kaname-saas-guard` の URL 安全性チェックに連結し、QR デコード URL を SaaS チェッカに通す
- **タイミング攻撃対策**: `kaname-crypto` 内の HMAC/署名比較を `subtle::ConstantTimeEq` で統一 (要 `subtle` クレート追加)

### 9.4 関連テスト

`kaname-screen` テスト数: 44 → 56 (+12)
- `unicode_tag_injection_blocked_in_screen`
- `extract_unicode_tag_decodes_payload` / `extract_unicode_tag_returns_none_for_normal_text`
- `ansi_escape_detected_in_audit` / `osc_hyperlink_spoof_detected`
- `carriage_return_overwrite_detected` / `crlf_alone_passes_audit`
- `unicode_tag_in_audit_output_detected`
- `normalize_strips_unicode_tag_chars`
- `cyrillic_homoglyph_override_blocked` / `greek_homoglyph_override_blocked`
- `homoglyph_to_ascii_maps_known_lookalikes`

---

## 10. Qiita/Zenn 追加調査 (v1.2 — 2026-06-21 後半)

第 2 ラウンドの調査で発見した BEC・MLS・並行性領域の改善を実装。

### 10.1 発見された新攻撃クラス

| ID | 攻撃名 | 出典 | 概要 |
|---|---|---|---|
| **B1** | スレッドハイジャック (口座差替) | [PSI 解説](https://www.psi.co.jp/topics/2026/nl_20260105_1.html) / [ジュピターテクノロジー](https://blog.jtc-i.co.jp/2026/01/mail-security.html) | 数週間の会話観察後、振込タイミングで本文の口座番号のみ差し替え。DMARC/SPF/DKIM 全通過 |
| **M1** | MLS Welcome リプレイ | [openmls docs](https://docs.rs/openmls/latest/openmls/) | openmls 自体は Welcome の `(group_id, epoch)` 重複を検知しない |
| **C1** | tokio async-await mutex デッドロック | [turso.tech](https://turso.tech/blog/how-to-deadlock-tokio-application-in-rust-with-just-a-single-mutex) | 単一 std::sync::Mutex でも `.await` 跨ぎ保持で確実にデッドロック |

### 10.2 適用した改善

| # | 対象 | 改善 | 優先度 |
|---|---|---|---|
| **C1-fix** | `Cargo.toml` (workspace.lints.clippy) | `await_holding_lock` / `await_holding_refcell_ref` を `deny` で workspace 全体に適用 | **P0** |
| **B1-fix** | `kaname-bec::account_diff` (新規モジュール) | スレッドハイジャック検出: 過去スレッドと現在メールから 7-8 桁数字 (口座番号) を抽出し集合差分。「変更」「振込先」キーワード重み付け | **P0** |
| **M1-fix** | `kaname-mls::MlsMailClient` | `seen_welcomes: HashSet<(ConversationId, u64)>` で `(conv_id, epoch)` 重複を追跡。リプレイ時は `MlsMailError::WelcomeReplay` で拒否 | **P1** |

### 10.3 残課題 (Sprint N+3)

- **B1 拡張**: 過去スレッドソースを JMAP から取得し `assess()` パイプラインに組み込み
- **OAuth トークン窃取兆候検知**: 送信元 IP / User-Agent 急変を MLS audit log と突合
- **PII 5 段階階層検出**: regex → keyword → 形態素 → NER → LLM (Qualiteg 推奨)
- **Double HMAC Verification**: `kaname-crypto` 内の HMAC 比較を `subtle::ConstantTimeEq` + Double HMAC パターンに統一

### 10.4 関連テスト

- `kaname-bec`: `account_diff` モジュール 11 テスト追加 (差替検出、全角数字、英日キーワード、低リスクケース)
- `kaname-mls`: `welcome_リプレイは2回目以降拒否される` 1 テスト追加

ワークスペース合計テスト数: 865 → 897 (+32)。

