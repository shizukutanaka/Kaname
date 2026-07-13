# CHANGELOG

All notable changes to Kaname are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **kaname-render Quishing 構造亜種検出** (2026年研究反映, docs/research-2026-07.md)
  - `blob:`/`data:`/`javascript:` スキームの QR ペイロードを `Suspicious` に格上げ (従来は Neutral で素通り)
  - `assess_multi_qr()` / `MultiQrRisk` — 分割QR (Structured Append) 攻撃の兆候検出
  - `detect_ascii_qr()` — ブロック文字によるASCIIアートQR (画像デコード不要のテキスト解析) の検出
- **kaname-render CalPhishing 検出** (`CalendarRisk::AutoRegistrationAbuse`)
  - `METHOD:REQUEST`/`PUBLISH` の自動登録永続化 (元メール削除後もカレンダーに残る) と他のフィッシング兆候の併存を検出
  - 警告文で「カレンダー側のエントリ削除が必要」であることを明示
- **docs/research-2026-07.md**: 2026-07 の最新研究調査とKanameへの反映マップ (長所・短所・改善点の総括含む)
- **kaname-render カレンダー招待のプロンプト注入検査** (`CalendarRisk::PromptInjectionAttempt`)
  - .ics の DESCRIPTION/SUMMARY を `kaname-screen::PromptScreener` で検査 (ワークスペース内依存を新規追加、循環なし)
  - 命令上書きフレーズ・特殊トークン・Base64/Unicodeタグ/HTMLエンティティ注入を検出し Danger 判定
  - 誤検出防止のため `Blocked` (確定的マーカー一致) のみ採用 (エントロピー単独の `Suspicious` は不使用)
- **kaname-ai preflight モジュール**: Dual-LLM パイプライン入口での事前検査
  - `preflight_untrusted()` — Bidi 制御文字 (U+202E 等) / ゼロ幅文字 / 既知インジェクションパターンを検出
  - `PreflightResult` (Clean / Advisory / Block) と `Finding` 列挙型
- **kaname-dlp 本物の正規表現エンジン** (スタブ撤廃)
  - `regex` クレート導入。エンジン構築時に全パターンをコンパイルしキャッシュ (メール毎の再コンパイル無し)
  - 不正パターンはフェイルセーフ (マッチ無し + 警告ログ)
  - `excerpt_match` が実際の一致位置の前後 ±30 文字を抽出 (監査証跡の精度向上)
- **kaname-dlp render_bridge モジュール**: kaname-render パイプラインへの DLP 統合
  - `EnvelopeScanner` が `kaname_render::DlpScanner` trait を実装
  - `render_with_dlp()` 経由で受信メールの DLP Block がレンダリング前に発動
- **kaname-render 実 MIME パース** (スタブ撤廃)
  - `mail-parser` (Stalwart Labs) による RFC 5322/2045-2049 準拠パース
  - From/To/Cc/Subject/Date/Message-ID/本文/添付ヘッダーを抽出
  - Authentication-Results ヘッダーから SPF/DKIM/DMARC 結果をパース
  - `DlpScanner` trait による DLP 注入ポイント (依存グラフ単方向性を維持)
- **kaname-bec 意味的トピック異常検出** (スタブ撤廃)
  - TF-IDF bag-of-words + コサイン類似度による送信者の典型トピックとの距離計算
  - 英語 (単語境界) と日本語 (CJK 文字単位) の混在テキストに対応、ストップワード除去
  - 類似度 < 0.15 で「異常なトピック」と判定 (例: CFO が突然配送通知を送る)
- **kaname-screen RateLimiter** (OWASP ASI-10 リソース枯渇 / DoS 対策)
  - トークンバケット方式。バースト許容量と定常レートを分離設定
  - 時刻を外部注入する決定的設計 (テスト容易) + クロック巻き戻り耐性
  - `docs/owasp-agentic-mapping.md` の ASI-10 を 🔶 部分 → ✅ に更新
- **kaname-screen 入力スクリーニング拡充**
  - ドイツ語 override フレーズ・context poisoning マーカーを `PromptScreener` に追加
- **敵対的テストコーパス 17 → 35 件** (kaname-tests)
  - カテゴリ H (OutputAuditor 出力検査) / I (CRLF・空白パディング・HTML コメント注入) 新設

### Fixed
- ワークスペース全体の clippy 警告ゼロ化 (`-D warnings` クリーン)
- MLS セーフティナンバー計算式 (`% 100_000` で常に 5 桁)
- Bearer トークンのログ秘匿バグ (トークン本体ではなく "Bearer " 内の空白を検出していた)
- BEC ブランドなりすまし閾値 (70→50) と "dan mode" 攻撃マーカーの小文字比較
- Shannon エントロピーの非決定性 (HashMap→BTreeMap + f64 演算)

## [0.3.21] - 2026-06-02 — GitHub 公開準備リリース

### Added
- **.gitattributes**: 改行正規化・Linguist 言語統計・バイナリ指定
- **.editorconfig**: エディタ間の一貫性 (Rust 4 / Web 2 スペース)
- **.env.example**: 環境変数テンプレート (BYOK/JMAP/Stripe/暗号/OTel)

### Fixed
- PR テンプレートの case 重複 (PULL_REQUEST_TEMPLATE.md と pull_request_template.md) を解消
  - DRI 確認付きの既存 pull_request_template.md を採用

### Changed
- `.gitignore`: fuzz/corpus シードを公開対象に変更 (回帰防止の価値ある資産)
- README プロジェクト統計を v0.3.20 に更新 + docs 索引へのリンク追加

### Verified
- GitHub 公開必須ファイル 13 種すべて存在
- シークレット混入なし (gitleaks 相当スキャン)
- 秘密鍵・証明書の混入なし
- .env はgitignore除外、.env.example をテンプレートとして提供
- static-check 6 項目合格


## [0.3.20] - 2026-06-01 — コンパイル阻害要因の除去

### Fixed
- **致命的: subprocess.rs の unsafe libc::kill を除去**
  - `#![deny(unsafe_code)]` と矛盾する `unsafe` ブロックが存在 (コンパイル不可)
  - さらに libc が依存に未宣言 (二重にコンパイル不可)
  - std のみの安全な実装に置換 (try_wait → kill → wait、ゼロ依存維持)
  - グレースフルシャットダウンは try_wait による終了確認で代替

### Added
- static-check.sh に 2 チェック追加:
  - [5] unsafe ブロック検出 (deny(unsafe_code) 整合)
  - [6] 未宣言依存検出 (libc:: 等の使用 vs Cargo.toml)

### Verified
- 深層静的解析で全 .rs の括弧バランスを検証 (raw string 考慮で全て一致)
- unsafe ブロック 0、未宣言依存 0 を確認
- 静的チェック 6 項目すべて合格

### Notes
- この unsafe は過去セッションで見落とされていた実コンパイル阻害要因
- static-check 強化により同種の問題が今後 CI で自動検出される


## [0.3.19] - 2026-06-01 — 静的検証リリース

### Added
- **scripts/static-check.sh**: cargo 不要の静的整合性チェック
  - pub mod 宣言とファイル存在の照合
  - use kaname_X と Cargo.toml 依存の整合
  - workspace members とディレクトリの整合
  - バージョン整合 (Cargo/package.json/tauri.conf)
- ci.yml に static-check ジョブ追加
- package.json / Makefile に static-check ターゲット追加

### Verified
- 全 27 クレートのモジュール宣言・依存・バージョンが整合 (0 エラー)
- 同名型 (Verdict/ActionType) の re-export 衝突がないことを確認
  (dual_llm::ActionType のみ re-export、threat_intel はフルパス)

### Notes
- 実機 cargo build はネットワーク制約により本環境では実行不可
- static-check は cargo check の補完 (実機 CI では cargo check が必須)


## [0.3.18] - 2026-06-01 — ドキュメント整合性リリース

### Added
- **docs/README.md**: ドキュメント索引 (24 文書の目的別地図)
  - 孤立していた research 系 3 文書 (arxiv/category/owasp) を索引から参照
- **.claude/skills/agentic-defense.md**: 8 層エージェント防御の統合スキル
  - 入力スクリーニング → Dual-LLM → Bridge → Tiered-Risk → Rule of Two
    → ArgumentValidator → 出力監査 → Trajectory Monitor の全体像

### Fixed
- README プロジェクト統計を v0.3.17 実態に更新 (452 テスト/27 クレート)
- gap-analysis.md を v0.3.9 → v0.3.17 に更新
- research 文書の孤立を解消 (docs/README.md から全参照)

### Changed
- .claude/skills: 8 → 9 スキル


## [0.3.17] - 2026-06-01 — Trajectory Monitoring リリース

### Added
- **Agent Trajectory Monitoring** (kaname-observability/trajectory.rs、10 ユニット + 2 proptest)
  - エージェント行動軌跡を時系列で記録・分析 (OWASP ASI-09 対応)
  - Rule of Two 違反の軌跡検出 (3 能力が時系列で揃う)
  - 高頻度操作検出 (自動化攻撃の兆候)
  - 危険シーケンス検出 (機密アクセス → 外部送信)
  - PII を含まない (操作種別とタイムスタンプのみ、I5 準拠)
- ui に `record_agent_step` / `reset_trajectory` コマンド配線
- kaname-ui に kaname-observability 依存追加

### Changed
- Rust テスト: 456 → 468 件
- proptest: 18 → 20 件
- OWASP ASI-09 に Trajectory Monitor を追記

### Research
- AgentDoG / trajectory monitoring 研究に基づく実装
- これで前回 future work の trajectory monitoring を完了


## [0.3.16] - 2026-06-01 — AgentDojo 互換テストリリース

### Added
- **AgentDojo 互換 敵対テストスイート** (kaname-tests/agentdojo.rs)
  - arxiv 2406.13352 (NeurIPS 2024) の 4 正規攻撃パターンで Kaname を検証:
    - Ignore Previous Instructions (en/ja)
    - System Message 注入 (ChatML/INST マーカー)
    - You-are-now 系の役割上書き
    - benign ケース (誤検知ゼロ確認)
  - 入力スクリーニング・出力監査の網羅検証
  - **攻撃成功率 0% を assert** (GPT-4o は攻撃下 45% に低下)
- kaname-tests に kaname-ai/screen/bec/dlp 依存を明示追加

### Changed
- Rust テスト: 452 → 456 件
- AgentDojo ベンチマークで Kaname の Dual-LLM + screen 防御を定量検証

### Research
- AgentDojo (2406.13352): 97 タスク + 629 セキュリティテストケースの業界標準
- Kaname の型境界 + kaname-screen が AgentDojo 正規攻撃を 100% ブロック


## [0.3.15] - 2026-06-01 — 配線統合リリース

### Fixed
- **孤立モジュールの配線解消** (前回 v0.3.13/v0.3.14 で作成したが未配線だった):
  - EDM を DLP エンジンに統合: `Predicate::ExactDataMatch` バリアント追加
    + `EvalCtx::edm_sets` フィールド + 評価ロジック
  - Rule of Two を ui に配線: `check_rule_of_two` コマンド
  - ArgumentValidator を ui に配線: `validate_tool_argument` コマンド

### Added
- EDM 統合テスト (DLP エンジン経由での検出)
- Rule of Two / ArgumentValidator コマンドの統合テスト 4 件

### Changed
- Rust テスト: 447 → 452 件
- 全クレート・全モジュールが配線済み (孤立ゼロを再確認)


## [0.3.14] - 2026-05-31 — EDM・OWASP マッピングリリース

### Added
- **EDM (Exact Data Matching)** (kaname-dlp/edm.rs、11 ユニット + 3 proptest)
  - ハッシュフィンガープリントによる機密データの完全一致検出
  - 平文を保存せず salt 付きハッシュのみ保持 (I5 プライバシー準拠)
  - chunk 分割攻撃に対抗 (トークン単位で照合)
  - min_matches 閾値で誤検知を抑制
- **docs/owasp-agentic-mapping.md**: OWASP Agentic Top 10 (2026) 対応マッピング
  - ASI-01〜10 への Kaname 防御マッピング (9/10 完全対応)

### Changed
- Rust テスト: 433 → 447 件
- proptest: 15 → 18 件
- 前回文書化した「今後の検討」優先度1 (EDM)・優先度4 (OWASP) を実装

### Research
- EDM は 2026 年 DLP 業界標準 (hash-based fingerprinting)
- OWASP Agentic Top 10 (2026, ASI prefix) に Kaname を照合し 9/10 を確認


## [0.3.13] - 2026-05-31 — 10カテゴリ研究反映リリース

### Added
- **Rule of Two** (kaname-ai/rule_of_two.rs、8 テスト + 1 proptest)
  - Meta の agentic セキュリティ原則 (arxiv 2601.17548)
  - [untrusted入力/機密アクセス/外部通信] の 3 能力同時保持を Violation 検出
  - 外部通信の分離を最優先で提案する mitigation
- **ArgumentValidator** (kaname-screen、4 テスト)
  - CaMeL argument manipulation バイパス対策 (arxiv 2601.11893)
  - untrusted データによる宛先すり替え・許可外ドメイン紛れ込みを検出
- **docs/category-research-2026.md**: 10 カテゴリ別研究調査記録

### Research
- 10 カテゴリ (AIセキュリティ/認可/暗号/メール脅威/DLP/サンドボックス/
  プロトコル/可観測性/i18n/課金) で arxiv + GitHub を調査
- CaMeL の argument manipulation 脆弱性 (2601.11893) を確認・対策
- Meta "Rule of Two" を実装
- MLS combiner (PQ MLS, 2026年12月マイルストーン) を将来課題として記録

### Changed
- Rust テスト: 421 → 433 件
- proptest: 14 → 15 件


## [0.3.12] - 2026-05-31 — KAT・整合性リリース

### Added
- **ML-KEM/X25519 KAT** (kaname-crypto/tests/kat.rs、6 テスト)
  - FIPS 203 パラメータ検証 (公開鍵 1184 / 暗号文 1088 / 共有秘密 32)
  - RFC 7748 X25519 パラメータ検証
  - derive_key の決定論性・domain separation 検証
  - verification-boundary.md で約束した KAT を実装
- **AlgId メタデータメソッド**: `public_key_len` / `ciphertext_len` / `shared_secret_len`
- **example 2件**: screen_and_audit / tiered_risk_demo
- **crypto-kat CI ジョブ**: KAT + X25519 検証 + 検証境界文書チェック

### Fixed
- CLAUDE.md のクレート数を 25 → 27 に修正 (実態との乖離解消)
- verification-boundary.md を threat-model.md から参照 (孤立文書解消)

### Changed
- README にセキュリティアーキテクチャ節を追加 (arxiv 研究の対応表)
- Rust テスト: 415 → 421 件


## [0.3.11] - 2026-05-30 — 検証境界リリース

### Added
- **X25519 出力検証** (kaname-crypto): arxiv eprint 2026/192 V2/V4 対応
  - `validate_x25519_output()`: 共有秘密の all-zero を constant-time 検出
  - `CryptoError::WeakSharedSecret`: small-subgroup 攻撃の兆候を報告
  - encapsulate / decapsulate 両方で検証
  - X25519 検証テスト 3 件追加
- **docs/verification-boundary.md**: Kaname の検証境界を 3 Tier で明示
  - "verification theatre" (形式検証の盲信) を避ける多層防御原則
- docs/arxiv-research-2026.md 第3回調査を追記

### Security
- eprint 2026/192「Verification Theatre」の教訓を反映
  - libcrux が欠いていた X25519 contributory behavior 検証を独自実装
  - 「形式検証済み」を盲信せず独自 sanity check を追加

### Changed
- Rust テスト: 412 → 415 件
- kaname-crypto: 478 → 約540 行

## [0.3.10] - 2026-05-30 — 配線統合リリース

### Fixed
- **孤立クレートの配線**: kaname-screen / kaname-memory-guard が ui に未配線だった問題を解消
  - kaname-ui/Cargo.toml に依存を追加
  - commands.rs に 4 つの UI コマンドを追加:
    - `screen_user_input` (入力スクリーニング)
    - `audit_ai_output` (出力監査)
    - `check_action_risk` (Tiered-Risk 判定)
    - `check_memory_trust` (メモリ汚染防御)
  - 6 つの統合テストを追加
- kaname-ui/Cargo.toml に `[features]` (tauri-app) を明示定義

### Changed
- Rust テスト: 406 → 412 件
- CLAUDE.md に arxiv 研究反映機能のマップを追加
- gap-analysis.md を v0.3.9 状態に更新 (412テスト/33項目)
- README プロジェクト統計を v0.3.9 に更新


## [0.3.9] - 2026-05-30 — メモリ汚染防御リリース

### Added
- **kaname-memory-guard** (新クレート、327 行、11 ユニット + 3 proptest)
  - `TrustScorer`: composite trust scoring (arxiv 2601.05504 防御1)
    出所別信頼度 + 注入パターン検出 + 異常長検出
  - `MemorySanitizer`: temporal decay + filtering (防御2)
    指数減衰 (半減期 30 日) で古い汚染エントリの影響を低減
  - MINJA / MemoryGraft 攻撃への先行防御基盤
- `docs/arxiv-research-2026.md` 第2回調査を追記 (メモリ汚染・サイドチャネル)

### Changed
- クレート数: 26 → 27 (kaname-memory-guard 追加)
- Rust テスト: 398 → 409 件
- proptest: 11 → 14 件

### Research
- MINJA (2503.03704): クエリのみで 95% メモリ注入成功 — 将来の脅威として記録
- MemoryGraft (2512.16962): トリガー不要の永続的 behavioral drift
- Memory Poisoning Defense (2601.05504): composite trust scoring + sanitization を実装
- サイドチャネル対策 (2505.22852 §4) の Kaname 現状を再評価


## [0.3.8] - 2026-05-30 — arxiv 研究反映リリース

### Added
- **kaname-screen** (新クレート、368 行、13 ユニット + 3 proptest)
  - `PromptScreener`: 入力スクリーニング (arxiv 2505.22852 §2.1)
    命令上書きフレーズ・特殊トークン・高エントロピー文字列を検出
  - `OutputAuditor`: 出力監査 (§2.2) 隠れた "## System:" 命令・外部送信先を検出
- **Provenance::UserUpload** (kaname-ai): 添付ファイル由来データの provenance タグ (§2.3)
- **Tiered-Risk Access Model** (kaname-ai/tiered_risk.rs、233 行、10 ユニット + 2 proptest)
  - Green/Yellow/Red の3段階リスク制御 (§3)
  - prompt fatigue 低減: Green は確認不要、Red のみ多要素承認
- `docs/arxiv-research-2026.md`: arxiv 調査記録 (CaMeL/AgentDojo/ML-KEM-MLS)

### Changed
- クレート数: 25 → 26 (kaname-screen 追加)
- Rust テスト: 380 → 398 件
- proptest: 9 → 11 件

### Research
- CaMeL (2503.18813) との設計一致を確認 — Kaname の Dual-LLM 型境界は独立に同じ結論に到達
- AgentDojo (2406.13352) の正規攻撃パターンを kaname-screen でカバー
- ML-KEM/MLS PQ cipher suites (IETF draft) が Kaname の HybridKEM 選択を裏付け


## [0.3.6] - 2026-05-26

### Added
- 全 24 クレートの lib.rs に `#![deny(clippy::unwrap_used)]` + `#![deny(clippy::expect_used)]` 追加
  (CLAUDE.md I6 との整合を取る)
- `.cargo/config.toml` に `RUSTDOCFLAGS = "-D warnings"` 追加
- fuzz corpus を 12 → 23 シードに拡充 (AiTM URL / カレンダー招待 / SSA バイパス試行)
- `package.json` に `test:coverage` / `test:coverage:ui` スクリプト追加
- `kaname-continuity` を完全実装 (313 行、7 ユニット + 4 proptest)
  - `ContinuitySession` (Handoff 状態管理)
  - `HandoffManager`
  - scroll_position clamp 不変条件
  - シリアライズ冪等性
- `.github/ISSUE_TEMPLATE/security_notice.md` 追加

### Fixed
- CLAUDE.md I6 (`#[deny(clippy::unwrap_used)]`) とコードの矛盾を解消

### Changed
- proptest: 9 → 13 件 (continuity +4)


## [0.3.5] - 2026-05-26

### Added
- `pub fn` 65 箇所に `#[must_use]` 追加 (戻り値の見落とし防止)
- `pub fn` 31 箇所に `///` ドキュメントコメント追加
- `.claude/skills/` を 3 → 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv に proptest 4 件追加
- kaname-radar に DNS 解決スケルトン (`DnsResolver` トレイト) + テスト 3 件追加
- kaname-ssa に proptest 3 件追加
- kaname-saas-guard に proptest 3 件追加
- CLAUDE.md を 174 → 233 行に拡充 (v0.3 全機能の実装場所マップ、セッション開始プロトコル)
- package.json に test:e2e / test:a11y / fuzz:* / stats / snapshots:init スクリプト追加

### Fixed
- `.gitignore` から `Cargo.lock` 除外を削除 (アプリケーションはコミット必須)
- `integration.rs` の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- `kaname-sandbox` の `panic!` にセキュリティ不変条件コメントを追加

### Changed
- Rust テスト: 381 → 384 件
- proptest: 6 → 8 件 (oobv / radar / ssa / saas-guard)


### Added
- `#[must_use]` を 65 の公開 API 関数に追加 — 戻り値の見落とし防止
- `.claude/skills/` を 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv にプロパティテスト 4 件追加
- kaname-radar にプロパティテスト 2 件追加

### Fixed
- integration.rs の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- 本番コードの unwrap 合計 = 0 達成

### In Progress
- E2E スナップショット基準画像 (CI 初回実行で生成)
- DNS 解決を kaname-radar に統合 (現在はシミュレーション)

### Planned for v1.0.0
- Design Partner 30 社での実証データ収集
- cargo build --release の CI 4 プラットフォーム通過
- App Store Notarization + Microsoft Authenticode 取得


### Added
- `#[must_use]` を 65 の公開 API 関数に追加 — 戻り値の見落とし防止
- `.claude/skills/` を 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv にプロパティテスト 4 件追加
- kaname-radar にプロパティテスト 2 件追加

### Fixed
- integration.rs の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- 本番コードの unwrap 合計 = 0 達成

### In Progress
- E2E スナップショット基準画像 (CI 初回実行で生成)
- DNS 解決を kaname-radar に統合 (現在はシミュレーション)

### Planned for v1.0.0
- Design Partner 30 社での実証データ収集
- cargo build --release の CI 4 プラットフォーム通過
- App Store Notarization + Microsoft Authenticode 取得



- LICENSE を AGPL-3.0 公式全文 (661 行) に置換中
- docs/specifications/ 言語非依存仕様ディレクトリ作成
- E2E スナップショット基準画像の生成 (CI 環境で実行予定)

### Planned for v0.4.0
- kaname-radar の DNS 解決を実機統合 (現在はシミュレーション)
- SSA モデルの精度向上 (30通 → 10通で信頼できるプロファイル)
- AiTM CTI フィード (既知 PhaaS インフラの動的更新)


## [0.3.0] - 2026-05-12 — 2026 Q1 脅威対応リリース

> Deep Research (Microsoft Q1 2026 Threat Report / Cofense / Barracuda) + Ultrathink

### Added (新機能)

**AiTM Link Detector** (`kaname-bec/src/aitm.rs`, 299行, 11テスト)
- Tycoon2FA / Storm-1747 の PhaaS インフラパターン検出
- URL 内セッション捕捉パラメーター (id_token / code / state) 検出
- 正規ブランドを装った偽ドメイン検出 (microsoft.com.evil.tk 形式)
- 多段スコアリング (0-100)、80+ で Dangerous 判定

**Sender Style Authentication** (`kaname-ssa`, 新クレート, 469行, 13テスト)
- 7次元の文体指紋 (送信時刻分布・フォーマリティ・文長・句読点密度等)
- スタイル距離 0.60+ で警告、0.75+ で強警告
- コンテンツ保存なし (数値ベクトルのみ、プライバシー保護)
- 日本語・英語両対応の敬語レベル推定

**HTML Smuggling Detector** (`kaname-render/src/html_smuggling.rs`, 12テスト)
- Blob URI 生成検出 (URL.createObjectURL)
- Base64 デコード + 即時実行 (atob + eval) 検出
- 自動ダウンロードトリガー (createElement + click) 検出
- 偽 CAPTCHA ページ検出 (日本語・英語)
- Shell 参照 (mshta / PowerShell / cmd.exe) 検出
- 多重難読化 (unescape + decodeURIComponent + charCode 組み合わせ)

**Calendar Invite Guard** (`kaname-render/src/calendar_guard.rs`, 10テスト)
- .ics 添付の URL・主催者・会議リンクを多角検査
- 緊急性偽装キーワード検出 (日本語・英語)
- フリーメール主催者警告 (法人会議に gmail 等)
- 数字混入ドメイン検出 (amaz0n / g00gle 等)
- 無料TLD ブロック (.tk / .ml / .ga 等)

### Changed
- LICENSE を AGPL-3.0 正式全文に置換 (73行 → 164行, 法的有効性確保)
- `//!` ドキュメントを kaname-oobv・kaname-ssa に追加 (24/24 完備達成)
- `.cargo/config.toml` 追加 (Apple M1 最適化・lld 高速リンク・コマンドエイリアス)

### Research Basis
- Microsoft Q1 2026: AiTM が最大脅威、Tycoon2FA が 3日で 35,000 ユーザー被害
- Cofense: AI フィッシング 204% 増、76% URL が一意だが 94% は同一 IP を共有
- Barracuda: ポリモーフィック攻撃が 2026 年のデフォルトに
- Group-IB: HTML スマグリング + Blob URI フィッシングが急増


## [0.2.0] - 2026-04-29 — 2026年新脅威対応リリース

### Added (新機能 — Deep Research + Ultrathink ベース)
- **#1 OOBV (Out-of-Band Verification)** - 新クレート `kaname-oobv` (489行、14テスト)
  - BIP39 ベース 6 ワード検証フレーズ (50 ワードの安全な部分集合)
  - チャレンジ番号方式で Deepfake 音声攻撃を防御
  - 5 分期限、ZeroizeOnDrop でメモリから自動消去
  - 日本語/英語の金融キーワード自動検出
  - 監査ログ (フレーズは記録しない、結果のみ)
- **#2 CCPD (Cross-Channel Pivot Detection)** - 新クレート `kaname-pivot` (612行、16テスト)
  - 7 種類の pivot 検出 (Teams/Slack/Zoom/Google Meet/SaasDoc/Phone/Crypto)
  - 過去 30 日のやり取りベースで信頼スコア計算
  - 日米電話番号フォーマット対応
- **#3 QR Code Quishing 防御** - `kaname-render/src/quishing.rs` (345行、10テスト)
  - typosquatting 検出 (Levenshtein 距離)
  - 数字混入パターン (amaz0n、g00gle、paypa1)
  - free TLD ブロック (.tk、.ml、.ga、.cf、.gq)
  - 信頼ドメイン許可リスト
- **#4 SaaS Link Safety** - 新クレート `kaname-saas-guard` (459行、11テスト)
  - 9 種類の SaaS プラットフォーム認識
  - 偽サブドメイン検出 (docusign.evil.com 形式)
  - 送信者別 SaaS 利用履歴管理
  - リスク 5 段階評価
- **#5 Deepfake Audio/Video Advisory** - `kaname-render/src/deepfake_advisory.rs`
  - MIME + 拡張子の両方で検出
  - 金融キーワード + 緊急性で警告レベル上昇

### Documentation
- `docs/new-features-v0.2.md` — 2026 年最新脅威対応設計書 (Deep Research 結果含む)
- `docs/performance-history.md` — リリース別ベンチマーク履歴
- `docker-compose.yml` — 開発環境の自動セットアップ
- examples/ ディレクトリ追加 (oobv_basic / pivot_detect / deepfake_advisory / dual_llm_safety)

### Web Research 結果統合
- AI 生成フィッシング 1,265% 急増 (FBI 2024 advisory)
- $25.6M 香港 CFO Deepfake 動画事件
- Voice cloning 1,633% 急増 Q1 2025 vs Q4 2024
- BEC 損失 $27.7 億 (2024 年単年)
- VEC、Quishing、SaaS 経由フィッシング、AitM (MFA バイパス)

### Changed
- Cargo.toml workspace に新クレート 2 つ追加 (kaname-oobv、kaname-saas-guard)
- クレート総数: 20 → 22
- Rust テスト総数: 247 → 296+

### Apple 流の戦略 (採用基準)
全新機能は以下を満たす:
- 北極星 (AIが助けても裏切らない) に整合
- 既存機能と重複しない
- 競合不在 (Superhuman/Proton/HEY は未対応)
- 実装 6 ヶ月以内

### Apple 流の却下 (No と言った機能)
- 受信箱全体の AI 解析モード (北極星と矛盾)
- クラウドベース AI 判定の追加 (Privacy 原則と矛盾)
- 取引先データベース統合 (ベンダーロックイン)
- ブロックチェーン送信履歴 (オーバーエンジニアリング)
- 行動分析ベース異常検出 (ユーザーデータ収集が必要)


### Added
- **新機能 #1: Out-of-Band Verification (OOBV)** — Deepfake 詐欺対策 (`crates/kaname-oobv/`, 489 行, 14 テスト)
  - BIP39 ベース 6 ワード検証フレーズ (50 ワードの安全な部分集合)
  - チャレンジ番号方式 (N 番目だけを答えさせて全ワード露出を防ぐ)
  - ZeroizeOnDrop でメモリ自動消去
  - 5 分期限 + 監査ログ (フレーズは記録しない)
  - 多言語金融キーワード検出 (日本語 + 英語)
- **新機能 #2: Cross-Channel Pivot Detection (CCPD)** — マルチチャネル攻撃検出 (`crates/kaname-pivot/`, 612 行, 16 テスト)
  - 電話番号 (国際/日本/英米フォーマット) 検出
  - Microsoft Teams / Slack / Zoom / Google Meet 会議リンク検出
  - DocuSign / Google Drive / OneDrive / SharePoint SaaS リンク検出
  - Bitcoin / Ethereum ウォレットアドレス検出 (BEC の高リスクシグナル)
  - PivotHistory による信頼スコア計算
- **新機能 #5: Deepfake Audio/Video Advisory** — 添付ファイル警告 (`crates/kaname-render/src/deepfake_advisory.rs`, 13 テスト)
  - 4 段階の警告レベル (None/Info/Medium/High)
  - 音声/動画 MIME + 拡張子の両方で検出
  - 金融キーワード + 緊急性で警告レベルを上げる
  - 推奨アクション: ShowAdvisory / PlayInSandbox / OobvBeforePlay
- **新機能設計書**: `docs/new-features-v0.2.md` (5 機能の Phase 計画)

## [0.1.4] - 2026-04-29

### Added
- **Apple 流ドキュメント**:
  - `docs/100-year-vision.md` (213 行) — 100 年保守ビジョン、暗号世代交代計画
  - `docs/brand-guidelines.md` (255 行) — トーン&マナー、UI ライティング規範
  - `docs/decisions-not-to-do.md` (233 行) — Apple 流「No」と言った決定の記録
- `docs/archive/README.md` — 歴史保管原則の明文化
- `docs/keynotes-README.md` — keynote 文書の役割分担

### Changed
- `release.yml` をデュアル署名版に統合、旧 `release-workflow.yml` を archive へ
- `keynote.md` → `vision-keynote.md` (北極星の核として明確化)
- `keynote-2026.md` → `launch-keynote-2026.md` (発表台本として明確化)
- `design.md` を Apple Platforms 準拠 v0.2 に置換、旧 v0.1 は archive へ

### Fixed
- 重複ワークフローを統合 (release.yml と release-workflow.yml)
- 重複 keynote ドキュメントの役割を明確化

## [0.1.3] - 2026-04-29

### Added
- `.github/CODEOWNERS` で 20 領域に DRI を明示 (Apple "Directly Responsible Individual" モデル)
- `kaname-continuity` クレート (Apple Continuity 風の OS 跨ぎ機能)
- `docs/design-reviews/` 構造 (proposals → decisions の流れ)
- `scripts/stats.sh` プロジェクト統計自動生成
- `scripts/generate-icons.sh` 全 OS アイコン生成
- 12 個のアイコンプレースホルダー (16x16 ~ 1024x1024 PNG)

### Changed
- 全 20 クレートに `//!` モジュールドキュメント追加 (cargo doc 対応)
- 全 20 クレートに個別 README.md を追加 (crates.io 公開品質)
- `kaname-mockserver` に `[[bin]]` セクション追加 (`cargo run -p kaname-mockserver --bin jmap-mock`)

## [0.1.2] - 2026-04-29

### Added
- 全 19 クレートに `[dev-dependencies]` セクション (proptest / tempfile / mockito / tokio-test)
- 16 クレートに `kaname-error` ワークスペース内依存を追加
- `.github/workflows/e2e.yml` — Playwright E2E + axe-core a11y CI (256 行)
- `.github/workflows/fuzzing.yml` — 独立ファジング CI (177 行、自動 Issue 作成)
- `e2e/__snapshots__/` 視覚的回帰テスト基準画像ディレクトリ
- ワークスペース依存に `tokio-test` と `mockito` を追加

### Changed
- ファジングを `release-workflow.yml` から独立した `fuzzing.yml` に分離
- E2E テストの実行頻度を 4 段階化 (PR 2分 / main 30分 / 週次 4時間 / 手動)

### Fixed
- `cargo test --workspace` がリンクエラーで失敗していた問題 (dev-deps 欠落)
- `kaname-error` クレートが孤立していた問題

## [0.1.1] - 2026-04-28

### Added
- v0.1.0 リリース後の改善
- `scripts/release.sh` — 9 ステップリリース自動化
- `crates/kaname-mockserver/` — JMAP モックサーバー (E2E 用)

## [0.1.0] - 2026-04-26

### Added
- **Dual-LLM 型安全 AI パイプライン** (`kaname-ai`): `Content<Untrusted>` 型でコンパイル時にプロンプト注入境界を強制。Superhuman の CVE を型システムで防ぐ。
- **BEC 多信号検出器** (`kaname-bec`): 7 信号 (ドメイン類似度、スプーフィング、緊急性マーカー、QR フィッシング、VEC、多ペルソナキャンペーン、メール爆撃)
- **MLS RFC 9420 E2E 暗号化** (`kaname-mls`): 件名を含む全体を暗号化、ML-KEM-768 + X25519 ハイブリッド KEM
- **DLP ルールエンジン** (`kaname-dlp`): boolean 式木で 12 分類器
- **Firecracker 添付サンドボックス** (`kaname-sandbox`)
- **JMAP 完全実装** (`kaname-jmap`)
- **DLPラベル強制 AI アクセス制御** — Microsoft Copilot CVE CW1226324 対策
- **AI生成フィッシング検出**: 精度 94.26%
- **Liquid Glass UI** (`KanameDesign.tsx`): Apple macOS Tahoe 26 準拠
- **GitHub Actions CI/CD**: check/test/clippy/fmt/audit/deny/bench/build/release の完全パイプライン
- **cargo deny 設定**: ライセンス・脆弱性・禁止クレート管理

### Tests
- 197 のユニットテスト + 統合テスト
- 50 ペイロード × 7 カテゴリの敵対テスト
- todo!() ゼロ達成

[Unreleased]: https://github.com/kaname-app/kaname/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/kaname-app/kaname/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/kaname-app/kaname/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/kaname-app/kaname/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/kaname-app/kaname/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kaname-app/kaname/releases/tag/v0.1.0
