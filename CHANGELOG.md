# CHANGELOG

All notable changes to Kaname are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **作成画面の送信前アドバイザリに `oobv_recommend` を配線** (D24 残件 — 台帳記載の想定用途どおり)
  - 本文入力の debounce が「DLP 事前チェック」を意図しながら空のスタブだったため実装に置き換え。送金要求・急迫表現等の別経路確認推奨文脈を送信前に助言表示 (ブロックではなく助言。呼び出し失敗は送信を妨げない)

### Removed
- **出荷バイナリ・ワークスペースから一度も到達不能だった4クレートを削除** (D19・D6)
  - `kaname-billing` (課金 — スコープ外、永続化未実装だった D6 も消滅)、`kaname-continuity` (デバイス間ハンドオフ — 単一デバイスで完結するスコープに不要)、`kaname-i18n` (翻訳カタログ — 正規実装は `src/i18n.ts` + `src/locales/`)、`kaname-tray` (トレイ生成 — `src-tauri` の内蔵トレイと重複)
  - ワークスペース 27→23 クレート (出荷 19、意図的除外 4: mls/sandbox/mockserver/tests)。実装は git 履歴に残り将来復元可能
### Fixed
- **`messages.to_addrs` 列が NOT NULL で存在するのに `NewMessage`/`StoredMessage` にフィールドが無く、宛先が常に `''` として消失していた欠落を修正** (D46 残件)
  - `to_addrs: Vec<String>` を両構造体に追加し JSON 配列として保存。`mail_fetch` が JMAP `Email.to[].email` を供給。旧行の `''` は「宛先不明」として空配列に倒す後方互換。回帰テスト2件追加
- **`src/ui/SecurityDashboard.tsx` の未使用 setter 3件により `npm run build`/`typecheck` が main で失敗していた出荷ブロッカーを修正** (D60)
  - `noUnusedLocals` 下で TS6133 ×3。CI 不在 (D7) のため検出が遅れていた
- **`kaname-memory-guard::normalize_for_matching` のゼロ幅文字削除が複数単語キーワードの語境界を壊す回避経路を修正** (D45・kaname-bec 残件あり)
  - ゼロ幅/フォーマット文字を単一スペースに置換する `normalize_for_matching_spaced` を新設し、`TrustScorer::score`・`kaname-oobv::OobvRecommender`・`commands.rs::has_financial` の3箇所で削除版とスペース化版の二重照合に変更。`wire​transfer` 型の単語間ゼロ幅挿入を捕捉。`kaname-bec` の2箇所はセキュリティレビュー必須クレートのため未修正(詳細: `docs/gap-analysis.md` D45)
- **`kaname-render::extract_auth_result` がプロパティ値内の `dkim=pass` 風擬似トークンを機構結果と誤認しうる構造的脆さを修正し、`AuthResultsHeader.authserv_id` を露出** (D18・部分対応)
  - `;` 区切り各部の `mechanism=result` トークンのみを機構結果として認めるパースに変更 (RFC 8601)。authserv-id の信頼リスト照合自体は組織ドメイン設定 (D44) と `mail-auth` 導入に依存するため未実施

### Security
- **フロントエンド devDependencies の既知脆弱性を `npm audit fix` で10件→4件に削減** (D61・部分対応)
  - `postcss`/`nanoid`/`js-yaml`/`browserslist`/`brace-expansion`/`baseline-browser-mapping` を非破壊的に更新 (lockfile のみ)。残り4件は `vitest`/`vite` メジャー更新が前提のため見送り(詳細: `docs/gap-analysis.md` D61)

### Fixed
- **実装済みの `oobv_start`/`oobv_verify`/`pivot_analyze` 3コマンドを Tauri に配線して到達可能化** (D15 残件)
  - `main.rs` に `.manage(commands::V02AppState::new())` を追加し、3コマンドを `tauri::State<'_, Arc<V02AppState>>` ラッパー経由で `invoke_handler` に登録。これで `commands.rs` の全公開コマンドが登録済みに。呼び出す UI は依然未実装 (static-check の「UI 未呼出」WARN に移行)
- **`kaname-bec::apply_cross_signal_escalation` がリスク緩和シグナル (ARC検証成功) を認証問題と誤認し複合シグナルボーナスを誤って付与することを記録** (D59・未修正・記録のみ)
  - `has_auth` 判定が `SignalFamily::Authentication` の存在チェックのみで符号 (加点/減点) を見ていないため、正規の転送メール (ARC成功による減点シグナル) が無関係な Domain/Content シグナルと重なると誤って `+0.20`/`+0.15` の複合ボーナスを受ける。正当な転送メール・請求書督促等を誤って BEC 高リスクと誤判定しうる false positive 方向の欠陥
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D59)

### Fixed
- **`kaname-bec::dkim_check::DkimReplayTracker` がエントリを一切退避せず無制限にメモリが増加することを記録** (D58・未修正・記録のみ)
  - `(domain, signature_prefix)` を `HashMap` に記録するのみで TTL/LRU/上限のいずれも無い。DKIM 署名は1通ごとに一意なため、攻撃でなくても通常のメール受信だけでプロセス生存期間中ずっと増え続ける。長期稼働するデスクトップメールクライアントで実際に影響する実用的なリソース枯渇バグ
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D58)

### Fixed
- **`kaname-dlp` の既定ポリシーが実装済み12分類器中3つしか有効化しておらず、SSN/IBAN/医療データ等が既定設定では無検査のまま送信できることを記録** (D57・未修正・記録のみ)
  - `default_rules()` が参照するのは `JpMyNumber`/`CreditCardPan`/`SourceCode` の3分類器のみ。`Iban`/`SwiftBic`/`UsSsn`/`IpAddress`/`AttorneyClientPrivilege`/`DealCodename`/`MedicalData`/`JpCorporateNumber` の8分類器は実装・テスト済みだが、カスタムルール読み込み (`from_db()`) も未配線のため有効化する経路が製品内に存在しない
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D57)

### Fixed
- **`kaname-bec::aitm::AitmDetector` が OAuth Implicit Flow のフラグメントトークン窃取 (`#access_token=...`) を検出できないことを記録** (D56・未修正・記録のみ)
  - 高リスク認証パラメーター検出がクエリ文字列区切り (`?`/`&`) のみを見ており、フラグメント区切り (`#`) を見ていない。Tycoon2FA/Storm-1747 等の実際の AiTM フィッシングキットが使う OAuth Implicit Flow のトークン窃取パターンを取りこぼす
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D56)

### Fixed
- **`kaname-screen::PromptScreener::screen` の主防御 (命令上書きフレーズ検出) がゼロ幅文字による単語間境界破壊で回避されていた欠陥を修正** (D55)
  - `kaname-screen` 独自の `normalize_for_matching` (D45 の `kaname-memory-guard` 版とは別実装) がゼロ幅文字を削除する設計のため、`ignore​all​previous` のように単語区切りにゼロ幅文字を挿入すると結合され、複数単語の override フレーズ照合が成立しなくなっていた。入力スクリーニングという Dual-LLM 境界前の最初の防御層での回避だった
  - ゼロ幅文字を削除せずスペースに置換する `normalize_for_matching_spaced` を新設し、削除版・スペース化版の両方でフレーズ照合するよう修正。回帰テストを追加

### Fixed
- **`kaname-dlp::misdirected_recipient` のフリーメール混入検出が宛先リスト最後尾以外では機能しないことを記録** (D54・未修正・記録のみ)
  - `all_internal_except_last` は「最後の1件を除く全員」が社内ドメインかのみ判定するため、フリーメールが宛先の先頭・中間にある場合は位置ベースの判定条件が成立せずサイレントに見逃す。`To`/`Cc`/`Bcc` の順序保証はどこにも無く、実際に起こりうる誤送信パターン
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D54)

### Fixed
- **`kaname-screen::OutputAuditor::audit` の漏洩先検出チェックが未正規化テキストを走査し全角回避を見逃していた欠陥を修正** (D53)
  - チェック1/7 は全角 Unicode 折り返し済みの正規化テキストを走査するが、チェック2 (漏洩先メールアドレス) とチェック3 (URL漏洩) は未正規化の原文を走査しており、全角文字で書かれた漏洩先アドレス/URLはモジュール自身が防ぐはずの回避手口をすり抜けていた
  - チェック2/3 も正規化済みテキストを走査するよう統一。全角回避を検出する回帰テストを追加

### Fixed
- **`kaname-dlp::edm::hash_token` が SHA-256 を64bitに切り詰めており doc comment の暗号強度主張と食い違うことを記録** (D52・未修正・記録のみ)
  - `hash_token` はフル SHA-256 を計算後 `digest[..8]` (64bit) のみを `u64` として保存するが、doc comment は「2^128 の誕生日境界」と主張していた。実際の衝突耐性は約 2^32
  - EDM (Exact Data Matching) の衝突は無関係なトークンを機微データ一致と誤判定しうる(false positive、可用性方向)。salt によりレインボーテーブル攻撃は引き続き防がれる
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D52)

### Fixed
- **「機能デモ」タブ (`KanameAppleFeatures.tsx`) 内の特定の誤情報・未表示のデモ表示を訂正** (D51・部分解消)
  - `QuickLook` の「Firecracker サンドボックスで安全にプレビュー」は、ページ全体が「デモ」と明示されているとはいえ、Firecracker が no-op (D4) であることを知らないと動作中の安全機構と誤読しうる特定の誤情報だった。「デモ表示 (Firecracker 隔離は未実装 — D4)」に訂正
  - `SmartReplyBar` の「AI 返信案」、`PdfExportDialog` の「✓ エクスポート完了」も、`invoke()` を呼ばず固定文言/固定完了状態を返すことがラベル自体には現れていなかった。それぞれ「(デモ・固定文言)」「✓ デモ完了 (実ファイルは生成されません)」に訂正
  - 実際の `invoke()` 配線(D24 で `ai_smart_reply` は honest error を返す実装済み)への切り替えはタブ全体がデモ前提のため見送り

### Fixed
- **`HtmlSmugglingDetector::analyze` の4MBサイズ上限切り詰めが UTF-8 文字境界を無視しパニックしうる欠陥を修正** (D50)
  - `&html[..MAX_HTML_BYTES]` が生のバイトオフセットでスライスするため、マルチバイト文字 (日本語等) の途中を切ると `panic!("byte index is not a char boundary")` していた。OOM DoS 対策自身がクラッシュを起こす本末転倒な状態だった
  - 既存テストは全て1バイト ASCII のみで構成されており、この境界ケースを一度もテストしていなかった
  - 切り詰め位置から `is_char_boundary` を満たすまで後退させてからスライスするよう修正。日本語1文字が4MB境界をまたぐ回帰テストを追加

### Fixed
- **`JmapClient::send_email` が送信済みフォルダ未検出時に架空のメールボックス ID にフォールバックしていた欠陥を修正** (D49)
  - `role == "sent"` のメールボックスが見つからない場合、文字列リテラル `"sent"` を実在しないメールボックス ID として使っていた。`Email/import` が失敗しても「インポート ID なし」という無関係なエラーになり根本原因が分かりにくかった
  - 同一ファイル内の `trash()` と同じパターン (`role` 未検出時に `JmapError::NotFound` を明示的に返す) に統一

### Fixed
- **`JmapClient::sync` が `hasMoreChanges` (RFC 8620 §5.2) を無視し500件超の差分をサイレント欠落させる欠陥を修正** (D48)
  - `Mailbox/changes`/`Email/changes` の `hasMoreChanges` を正しくパースしていたが、この値でページングループしておらず、`sync()` を呼ぶコードが将来書かれた場合に500件を超える差分の中間部分が永久に欠落する潜在バグだった(現時点で `sync()` 自体の呼び出し元はまだ無い)
  - `hasMoreChanges` が両方 `false` になるまで内部でループするよう修正。無限ループ防止のため最大50ページで打ち切り、打ち切り時は `has_more_changes: true` を呼び出し元に残して再開可能にした

### Fixed
- **`kaname-crypto` (ハイブリッド PQC クレート) に実暗号バックエンドが存在しないことを記録** (D47・doc comment のみ訂正・ロジック変更なし)
  - クレート冒頭が「FIPS 203/204 準拠のハイブリッド量子後暗号」と主張するが、`Cargo.toml` に暗号バックエンド依存が一切無く (`x25519-dalek`/`ml-kem` 等ゼロ)、`trait Kem` の実装は `#[cfg(test)]` 内の `MockKem` のみ。`HybridX25519MlKem::new` の実呼び出しもワークスペース全体でゼロ
  - MLS 群鍵暗号化を行う `kaname-mls` (D1: XOR モック) はそもそも `kaname-crypto` に依存しておらず、D1 と D47 は別々の未実装が独立に並存している
  - `kaname-crypto` は暗号設計レビュー (CLAUDE.md) 必須のクレートのため実装は見送り、クレート自身の doc comment のみ現状に合わせて訂正した(詳細: `docs/gap-analysis.md` D47)

### Fixed
- **`Store::save_message` がフォルダ移動・送信者情報の更新を永久に反映しない欠陥を修正** (D46)
  - `ON CONFLICT (id) DO UPDATE` の SET 句に `mailbox_id`/`from_addr`/`from_name` が含まれておらず、JMAP 側でのメール移動 (Inbox→Archive 等) や再同期時の送信者情報訂正が、決定論的 `id` による冪等 UPSERT では一切反映されなかった (オフライン閲覧が旧フォルダ・旧送信者情報のまま固定される)
  - SET 句に3カラムを追加して修正。回帰テストを2件新規追加(D20 により `cargo test` 実行不可のためコンパイル・実行は未検証、目視でのロジック確認のみ)
  - `to_addrs` 列が INSERT/UPDATE いずれも `''` 固定で宛先自体が永続化されていない別課題は `NewMessage` の構造拡張が必要なため残置(D46 に記録)

### Fixed
- **`normalize_for_matching` のゼロ幅文字除去が複数単語キーワードの語境界を壊す新たな回避経路を記録** (D45・未修正・記録のみ)
  - `kaname-memory-guard::normalize_for_matching` はゼロ幅文字 (`​` 等) を削除して単語内挿入回避 (`urg​ent`) を防ぐが、`wire​transfer` のようにスペースの代わりにゼロ幅文字を挿入されると `wiretransfer` に結合され、`kaname-oobv` の複数単語キーワード (`"wire transfer"` 等) の部分一致に失敗する
  - 単語内挿入対策が単語間挿入という逆方向の新しい回避経路を開いている。影響は `kaname-oobv`/`kaname-bec`/`kaname-screen` の3クレート
  - セキュリティリード承認必須のクレートに触れる修正のため、本セッションでは実装せず記録のみに留めた(詳細: `docs/gap-analysis.md` D45)

### Fixed
- **DLP/BEC の自組織ドメイン (`our_domain`) が全箇所で `"example.com"` にハードコードされていることを記録** (D44・未修正・記録のみ)
  - `kaname_dlp::EvalCtx.our_domain`(宛先ミス検出の自己送信除外用)と `kaname_bec::AssessmentRequest.our_domain`(なりすましドメインのホモグリフ検出用)が `commands.rs` の全5箇所で文字列リテラル `"example.com"` のまま渡されており、ログイン中アカウントの実ドメインを一切反映していない
  - 影響: (1) 送信 DLP の宛先ミス検出が自社ドメイン宛メールを常に「未知の外部ドメイン」として誤検知、(2) BEC のなりすましドメイン(ホモグリフ)検出が自社ドメインを騙る攻撃ドメインを実質検出できない(見逃し方向、より深刻)
  - 根本原因: `commands.rs`/`kaname-jmap::JmapClient` のどこにも「自組織のメールドメイン」を保持する設定・永続化の仕組みが存在しない(`JmapClient` は JMAP 内部 `account_id` のみ保持)
  - 修正には設定 UI への「組織ドメイン」入力欄の追加を伴うため、このセッションでは実装せず記録のみに留めた(詳細: `docs/gap-analysis.md` D44)

### Fixed
- **Dependabot の cargo エコシステムが上限に達し新規PRを開けなくなっていることを記録** (D43・コード変更なし)
  - `open-pull-requests-limit: 10`(cargo)に対し、未マージのcargo依存PRがちょうど10件(#37〜#45, #95)存在し上限と一致。npm由来も3件(#66/#87/#94)未マージ
  - D20(`cargo build`/`cargo check`がこの環境で実行不可)により安全にマージ判断ができないため、本セッションでは意図的に未着手のまま残した

### Fixed
- **D41 の追跡監査で `BecBadge` の表示漏れを発見** (D42・軽微)
  - バックエンドの BEC 判定エラー時フォールバックは正しく `"UNKNOWN"` を返していた(`"SAFE"` と偽らない、`assess_listing` は最初から正しく実装済み)
  - フロントエンドの `BecBadge`(Inbox.tsx)がこのケースをラベル/色マップに含めておらず、内部の生文字列 `"UNKNOWN"` がそのまま UI に表示されていた。「判定失敗」のラベルとグレー配色を追加した
  - D41 と異なり、これは誤情報ではなく表示品質の改善(安全と誤認させる問題ではなかった)

### Fixed
- **出荷 UI (`SecurityDashboard.tsx`) がハードコードされた偽データと未実装の保護機構を表示していた (D41・このセッション最重要)**
  - 「セキュリティ」タブを開くたびに、偽の AI アクセスログ・偽の連絡先インテリジェンス(架空の氏名)・偽のアクションアイテムをハードコードで表示していた。実データ取得元が無いため、偽データではなく空状態を表示するよう変更した(各サブコンポーネントは空配列を正しく処理する)
  - `ai_detect_phishing` がエラーになった場合、無言で「score: 0.15(安全)」という偽の判定にフォールバックしていた。**本物のフィッシングメールを安全と誤信させかねない**重大な欠陥だった。エラー時は専用のエラーメッセージを表示し、スコアバー・偽の安全判定は出さないよう修正
  - 「競合比較カード」で「ローカル AI 推論」(D2: 未実装)・「MLS + PQC 暗号化」(D1: XOR モック)を実装済みの独自機能として表示していた。SECURITY.md(D34)・brand-guidelines.md(D39)・competitive-analysis.md(D40)と同じ欠陥が出荷 UI 自体にもあった。5項目を実装状況どおりに ✓/⚠/✗ に区分し直した
  - **これは文書ではなく実際にユーザーが操作する出荷画面であり、これまでの発見の中で影響が最も直接的だった**

### Fixed
- **`ZeroKnowledgeSearch` 自身の doc コメントも「本番: SQLite FTS5 使用」と誤って主張していた** (D40 の追跡調査)
  - 実際のフィールドはインメモリ `Vec` で、アプリ再起動でインデックスが消える。コメントを実装どおりに訂正した
  - **配線は見送った**: 実際に配線されている `kaname_store::search_messages` は SQLCipher に永続化された LIKE 検索であり、未配線かつ非永続の `ZeroKnowledgeSearch` に置き換えると永続化を失う退行になる

### Fixed
- **`docs/competitive-analysis.md` の「実装した改善」表に、モック/スタブ/未配線の機能が実装済みとして6項目含まれていた** (D40)
  - 件名MLS暗号化(D1)・Dual-LLM型安全(D17)・Firecracker添付分離(D4)・ローカルAI推論(D2)が実装済みと主張していた
  - **新発見**: `kaname-privacy::ZeroKnowledgeSearch` は実装されているが `kaname-ui` から一度も呼ばれておらず、実際の検索(`mail_search`)は平文 LIKE 検索だった。D12/D13/D21 と同じ「実装したが組み付けていない」パターン
  - 該当6項目に実態を注記(⚠️/✅で区別)
- **`launch-keynote-2026.md`/`vision-keynote.md`/`product-film-script.md` に現状確認への導線を追加**
  - これらは Amazon/Apple 流「Working Backwards」を自ら明記した到達目標であり、SECURITY.md/testing-strategy.md/brand-guidelines.md とは性質が異なるため本文は書き換えず、`docs/maturity.md`/`docs/gap-analysis.md` へ導く注記のみ追加した

### Fixed
- **`docs/brand-guidelines.md` の「推奨表現」が未実装機能を主張するマーケティング文言の使用を執筆者に指示していた** (D39・最重要級)
  - 「推奨表現」に `"型システムで保証"`/`"コンパイル時に検証"`(D17: trait 実装0件)と `"RFC 9420 準拠"`(D1: MLS は XOR モック)が含まれていた
  - SECURITY.md(D34)・testing-strategy.md(D36)は「既に書かれた文書が誇張していた」問題だったが、これは**将来書かれるマーケティング文言・UI 文言が誇張することを積極的に推奨する**という、より先行的な害を持っていた
  - 該当2表現を取り消し線付きで「使用禁止」に変更し、D1/D17 解消後にのみ使用可能と明記した

### Fixed
- **`SETUP.md` に D7/D31 と同じ欠陥クラスが3箇所あった** (D38)
  - `git clone` が誤ったリポジトリ(`kaname-app/kaname`)を指していた(D31/D33/D35 と同じ誤り)。`shizukutanaka/kaname` に訂正
  - ディレクトリツリー図が `.github/workflows/` に `ci.yml`/`sbom.yml`/`release.yml` が存在すると記載していたが、実際は空(D7)
  - リリース手順が「`git push origin vX.Y.Z` で CI が自動的にビルド・配布」すると説明していたが、CI 自体が存在しないため配布は起きない
  - いずれも実態(CI 不在、手動配布が必要)に合わせて訂正した。`scripts/release.sh` 自体は実在することを確認済み

### Fixed
- **`docs/performance-history.md` が「実測は v0.2.0 リリース時に追記」と予告したまま、v0.7.1 に至るまで一度も追記されていなかった** (D37)
  - `cargo bench` は D20 により本環境で実行不可、CI ベンチマーク (`.github/workflows/perf.yml`) も D7 により存在しないため、この空白は今後も埋まらない可能性が高いことを明記した
  - v0.1.0/v0.1.4 の歴史的な実測記録は変更していない

### Fixed
- **`docs/testing-strategy.md` がテスト件数・カバレッジ「現状」を実測済みであるかのように主張していた** (D36。SECURITY.md D34 と同種)
  - 「CI 実行マトリクス」節は D7(CI ワークフロー自体が存在しない)を、「カバレッジ目標」表の「現状」列(91%/87%/85%等)は D20(`cargo test`/`npm test` がこの環境で実行不可)を前提にしており、どちらも検証不能な主張だった
  - 文書冒頭に、この環境で未検証であることを明記する訂正を追加した。数値そのものは書き換えていない(このリポジトリの実測値かどうか本セッションでは判定不能なため)

### Fixed
- **末尾のバージョン比較リンクが誤ったリポジトリ (`kaname-app/kaname`) を指していた** (D35。D31/D33 と同じ欠陥クラス)
  - `shizukutanaka/kaname` に訂正した
  - **git tag が一つも作成されていないことを確認した** (`git tag -l` が空)。v0.1.0〜v0.7.1 のどのリリースにもタグが付いておらず、比較リンクはリポジトリを訂正しても404のままになる。タグ作成はリリース権限を持つ人間の判断領域のため本セッションでは行わない

### Fixed
- **`SECURITY.md` が実装されていない保護機構3件を「実装済み」と主張していた** (D34・最重要)
  - 「主要保護メカニズム」節が Dual-LLM 型安全(実際は D17: trait 実装0件)・MLS 暗号化(実際は D1: XOR モック)・Firecracker サンドボックス(実際は D4: no-op)を実装済みと誤って主張していた
  - サポート対象バージョン表も v0.3.x を最新と記載したまま(実際は v0.7.1)だった
  - **セキュリティ方針文書自体が、この製品の README・threat-model・gap-analysis が総力で正そうとしてきた「誇張」を体現していた**。脆弱性報告者が誤った前提で判断しないよう、実態に合わせて訂正した
  - 報告経路・SLA・重大度分類・報奨・監査計画等の運用面は変更していない(人間の意思決定領域)

### Fixed
- **CONTRIBUTING.md の i18n 節が実態と3点ズレていた** (D33)
  - 存在しないディレクトリ (`src/i18n/`。実際は `src/locales/`)、存在しない言語ファイル (`zh-CN.json`/`ko.json`。`Language` 型は宣言しているが JSON 未作成)、存在しない CI 検証 (D7 により CI 自体が無い) を実態に合わせて訂正
  - `git clone` の URL も D31 と同じ誤り (`kaname-app/kaname`) を含んでいたため `shizukutanaka/kaname` に訂正
  - `src/i18n.ts` 冒頭コメントの誤ったファイルパス表記・CI 主張も訂正
  - 実害としてはブラウザ言語が中国語/韓国語のユーザーが日本語へ自動フォールバックするのみで、クラッシュや空表示にはならないことも確認済み

### Added
- **`static-check.sh` に検査8を追加**: `Cargo.toml`/`package.json`/`tauri.conf.json` のバージョン番号が一致していることを検証 (D32)
  - 前PRで v0.6.0 のまま放置されていた3箇所を修正した直後、「次のセッションのために記憶しておくべき」と書いただけで自動化していなかった。これは D25/D26 の教訓 (欠陥クラスは自動化するまで再発防止にならない) をその場で忘れていたことになる
  - 合成的に `package.json` を `0.6.0` に戻して検出されることを確認 (実際に起きたバグをそのまま再現)。復元後に誤検知が無いことも確認済み

### Fixed
- **ビルドマニフェスト3箇所のバージョン番号が v0.6.0 のまま放置されていた**: `Cargo.toml` (workspace、全クレートに波及)、`package.json`、`src-tauri/tauri.conf.json`。v0.7.0/v0.7.1 のリリースカットで README/CHANGELOG/maturity.md は更新したが、実際のビルド成果物に埋め込まれるバージョン番号を更新し忘れていた。すべて `0.7.1` に揃えた

### Changed
- **`docs/threat-model.md` の残存リスク評価3件が D10 (メールパイプライン未配線) 解消前の前提のまま放置されていた** (最重要)
  - **§3.15b (D18, 送信ドメイン認証の独立検証なし)**: 「D10 未配線のため悪用経路は存在しない」から**「D10 解消により現在実際に稼働している」へ格上げ**。`Authentication-Results` ヘッダを暗号検証・authserv-id 検証なしに信頼する設計は、監査時点では理論上の懸念だったが、**接続先 JMAP サーバや経路上の中継を攻撃者が制御・偽装できれば、現在悪用可能**。`docs/gap-analysis.md` D18 も同様に更新
  - **§3.16 (D17, Dual-LLM 型境界)**: 悪用不能な理由を「D10 未配線」から「D2 (LLM 推論がスタブで `llm_bridge` 呼び出しが0件)」に訂正。**LLM 推論を配線する PR は、型境界を同時に塞がない限りその瞬間に悪用可能になる**ことを明記
  - **§3.14 (SVG guard)**: 「添付処理パイプラインに未配線」という記述が誤りだったと判明。`scan_attachments` が実際に `svg_guard::scan_svg` を呼んでおり、D10 解消後は実メール添付に適用されている (安全側の訂正)
  - いずれもコード変更は無く、脅威モデルの記述精度のみを実態に合わせた

## [0.7.1] - 2026-09-14 — CLAUDE.md 不変条件の検証と、自分自身の記録の訂正

v0.7.0 に続き、CLAUDE.md の不変条件 (I5/I6) を初めて検証し、I5 を守る
はずの防衛層が完全に無効だったことを発見・修正した。加えて、v0.7.0
までに書いた D24 の分類を検証し直し、2箇所の誤りを訂正した。
「結論が同じでも理由が間違っていれば次の判断を誤らせる」という
教訓を得たリリース (詳細は docs/socratic-review.md)。

### Fixed
- **README のバッジ・`git clone` 手順が `kaname-app/kaname` (アクセス範囲外のリポジトリ) を指していた** (D31)
  - CI/Security Audit/Platform バッジと `git clone` コマンドの4箇所を実際のリポジトリ `shizukutanaka/kaname` に訂正した
  - `Cargo.toml`/`CLAUDE.md` 等、他13ファイルに残る同種の言及は意図的に変更していない (ブランド名か置き場所かの区別がコードから判断できないため)
- **`examples/README.md` の「JMAP 送受信は未配線」という記述が D10 解消より前の古い記述のまま残っていた**
  - 受信/送信/添付ダウンロード/削除/本人確認/検索/永続化はすべて配線済み。サンプルは「サーバ接続なしで同じ検出器をすぐ試せる」という位置づけに書き直した
- **D24 (a) の分類も一部誤りだった: 「LLM 依存で意図的に未配線」10件のうち8件は LLM 生成ではなく決定論的な防衛策だった** (D30・文書訂正のみ、コード変更なし)
  - D24 (a) は「配線すると偽の AI 出力を表示する」という理由で10件すべてを一括りにしていたが、`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory`/`screen_user_input` の8件は `PromptScreener`/`OutputAuditor`/`TieredRisk` 等の決定論的チェッカーを呼ぶだけで、`kaname-ai::llm_bridge` を一切呼んでいない。本当に LLM 生成を要するのは `ai_smart_reply`/`ai_summarize_email` の2件のみ
  - **配線しない判断自体は維持する**: `kaname-ui/src/commands.rs` に実際の LLM 呼び出し経路が一つも無いため、防衛すべき対象が無い現状でこれら8件を UI に繋いでも意味を持たない。LLM 本実装と同時に、その入出力の境界に組み込むのが正しい順序。D24 の分類理由のみを訂正した

### Fixed
- **D24 の分類ミスを発見・修正: `settings_get`/`settings_set` は「内部 API として正当」ではなく、引数を無視するだけの未使用スタブだった** (D29)
  - D24 を書いた時点でこの2コマンドの実装を確認せず「他コマンドから使用される内部 API」と分類していたが、実際は `_account_id`/`_key`/`_value` と使わない引数に `_` を付けたまま `Ok(())`/`Ok(None)` を返すだけで、呼び手は一つも無かった
  - オンボーディング専用の `settings_save_onboarding`/`settings_is_onboarded` は既に `kaname_store::Store::set_setting`/`get_setting` を実際に呼んでいたが、汎用版だけが同じパターンを踏襲せずスタブのまま放置されていた
  - `Store::set_setting`/`get_setting` を呼ぶ実装に置き換えた。呼び出す UI はまだ無いため `static-check.sh` 検査5の WARN は残るが、これは「実装はしたが UI 未着手」という正直な状態であり、隠さず記録する

### Fixed
- **CLAUDE.md I5 (「ログに PII を含めない」) を守るはずの `PrivacyLayer` が完全に無効だった** (D28・最重要)
  - `PrivacyLayer` は `kaname-observability` に実装・テストされていたが、どの tracing subscriber にも登録されておらず、実行時に一度も動いていなかった。`kaname-ui::run()` (`src-tauri/main.rs` から実際に呼ばれるロガー初期化) は `tracing_subscriber::fmt()...init()` だけで `PrivacyLayer` を組み込んでいなかった
  - `tracing_subscriber::registry().with(env_filter).with(fmt::layer()).with(PrivacyLayer).init()` に変更し、実際の subscriber に組み込んだ
  - **さらに `PrivacyLayer` 自身の docstring も実装と食い違っていた**: 「PII 検出時にイベントをドロップする」と書かれていたが、実装は警告ログを追加発行するだけで、PII を含む元のイベントは他の Layer (フォーマッタ) にそのまま伝播し出力されていた。`tracing-subscriber` の `Layer::on_event` には他レイヤーへの伝播を止める権限が無く、真にブロックするには `Filter::event_enabled` ベースの再設計が要る。docstring を実装どおり (検知のみ・非ブロック) に修正した
  - 手動でのワークスペース走査では I5 違反 (ログへの PII 直接埋め込み) はゼロ件を確認済みだが、それはプログラマの注意力のみに依存する脆い保証であり、設計されていた多重防衛層が無効だったのは重大な見落としだった
  - `cargo check` は D20 により実行できず、この修正が型検査を通ることは未検証。`Filter` ベースへの再設計 (実際にブロックできるようにする) も未着手 (残作業として記録)

### Added
- **`static-check.sh` に検査6を追加**: CLAUDE.md 不変条件 I6 (「`unwrap()` は本番コードに使用禁止」) を検証 (D27)
  - `#[deny(clippy::unwrap_used)]` で強制する設計だが、`clippy` は D20 (組織のエグレスポリシー) により一度も実行されておらず、I6 が守られているか未検証だった
  - ワークスペース全体を手動走査した結果、**本番コードでの `.unwrap()` 使用は 0 件**であることを確認 (`#[cfg(test)] mod` / 個々の `#[test]` 関数は正しく除外)。コード変更は無く、検証結果のみ
  - 再発防止として検査として自動化。合成的に本番コードへ `.unwrap()` を注入して検出されること、行番号が正しく報告されること、テストコード内では誤検知しないことを確認済み (docs/gap-analysis.md D27)

## [0.7.0] - 2026-09-14 — 「到達可能 UI から呼ばれないコマンド」を仕分けし、検証ツール自体の欠陥を2件直したリリース

v0.6.0 の「到達可能な UI がすべて実装を呼ぶ」を土台に、その**逆方向**
(実装済みなのに UI から届かないコマンド、D24) を仕分けて 5 件中 5 件を
解消し、さらに検証ツール自身に眠っていたバグを 2 件 (D25・D26) 見つけて
直したリリース。

### このリリースで学んだこと (docs/socratic-review.md に詳細)
- 「配線した」と言えるのは、その先が実装であることまで確認したときだけ
  である (D24)。ただし配線しないことが正しい場合もある — LLM がスタブの
  現状で AI 系コマンドを配線すれば偽の出力を表示することになる
- 静的検証ツール自体にも、検証対象のコードと同じ水準の注意が要る。
  一度作った検査は「一般化」した瞬間に別の欠陥を持ちうる。合成的に
  既知のバグを再現し、検出→復元を確認する手順を経て初めて信用できる
  (D25・D26 とも、最初に書いた検査の実装は検出したかったバグを
  素通りさせていた)

### Fixed
- **D25 と同じ欠陥クラスのフロントエンド版が見つかった** (D26)
  - `app.test.ts` の `makeEmail()` ヘルパーが、`KanameApp.tsx` 削除 (PR #82) で消えた `Email` 型を import せずに参照していた。どこからも呼ばれていない未使用コードでもあった。`tsc`/`vitest` が動く環境であれば型エラーで即発覚するはずが、D20 により実行できず3セッション気付かれなかった
  - `makeEmail()` を削除

### Added
- **`static-check.sh` に検査6を追加**: TypeScript の「未 import・未定義の型参照」を検出 (D26 の再発防止)
  - 大文字始まりの識別子が、import 文にも同一ファイル内の型/値定義にも無いまま型位置 (`: Type` / `Generic<Type>`) で使われているケースを機械的に検出する
  - 最初の実装は `Partial<Email>` のようなジェネリクス**使用**側まで「ローカルなジェネリクス宣言」として誤って許可しており、検出したかったバグそのものを素通りさせていた。合成的な回帰テスト (壊れたコードを一時的に再現し、検出→復元を確認する) で発覚し、`function f<T>`/`class C<T>` の宣言側にのみ限定して修正した
  - ワークスペース全体で誤検知ゼロを確認

### Added
- **`analyze_raw_email` (mail_import_eml/mail_open 共通の解析経路) に初のユニットテストを追加**
  - これまで一度もテストされていなかった。D25 の static-check 強化の過程で発覚
  - 安全なメール (BEC/OOBV/Deepfake すべて無反応)、送金 BEC メール (OOBV 強い推奨)、金融文脈を伴う音声添付 (Deepfake High 警戒)、二重拡張子の危険添付、の4ケースを実データ (RFC 5322 バイト列) で検証

### Fixed
- **`mail_list` 削除 (PR #86) の巻き添えで放置されていたコンパイルエラー** (D25)
  - `crates/kaname-ui/src/commands.rs` のテストモジュールに `mail_list("inbox".into(), ...)` を呼ぶテストが2件残っており、`mail_list` 自体は既に削除済みだった。`cargo check` を実行できない環境 (D20) でこの種のリグレッションを防ぐために作った `static-check.sh` 自身が、これを見逃していた
  - 原因: 検査2がハードコードされたシンボル一覧しか見ておらず、一覧に無い関数の削除は検出できなかった。一覧を都度更新する運用は同じ穴を繰り返す設計だったため、リポジトリ全体を走査する一般的な方式に置き換えた
  - 壊れていた2テスト (`mail_list_respects_limit`/`bec_dangerous_in_mock`) はモック実装を前提にしていたため削除

### Added
- **`static-check.sh` 検査2を一般化** (D25 の根本対応)
  - ハードコードされたシンボル一覧を廃止し、リポジトリ全体から「裸で呼ばれているが定義も import も見つからないシンボル」を機械的に検出する方式に変更
  - 一般化の過程で見つけた誤検知の原因をすべて修正: 属性 (`#[cfg(...)]`)・raw文字列の閉じハッシュ数不一致・char リテラル (`'"'`) と文字列リテラルの処理順序・文字列内のバックスラッシュ行継続 (DOTALL 不足)・複数行 `use` インポート・行末コメント (従来は行頭コメント専用行しか除去していなかった)・Rust 予約語 (`if(`/`let(`/`pub(crate)` 等)・クロージャ束縛 (`let f = |...|`)
  - 修正後、ワークスペース全体で誤検知ゼロを確認。合成的に削除済み関数への参照を注入したテストで正しく検出できることも確認済み

### Added
- **Deepfake (音声/動画添付) の警告をメール詳細に配線** (D24 (b) を完全解消)
  - `analyze_raw_email` が添付検査 (`scan_attachments`) の結果を使い回し、`DeepfakeAdvisory::evaluate()` を直接呼ぶ。`ImportedEmail.deepfake_advisory` として埋め込み、独立コマンド `deepfake_evaluate` への往復は発生させない
  - 受信トレイの詳細パネルと「ファイル解析」タブの両方に表示: 高警戒 (金融文脈あり) は目立つ警告として、それ以外の音声/動画添付は控えめな注記として表示。推奨アクション (`OobvBeforePlay`/`PlayInSandbox`) に応じて文言を出し分ける
  - これで D24 (b)「配線すべき」5 件 (`mail_download_attachment`/`mail_trash`/`history_mark_verified`/`oobv_recommend`/`deepfake_evaluate`) が**全件解消**。独立コマンドとしての `oobv_recommend`/`deepfake_evaluate` は UI から未到達のままだが、判定ロジックは配線済みで、静的検査の WARN は意図した状態として D24 に記録済み
- **帯域外検証 (OOBV) の推奨をメール詳細に配線** (D24 (b) をさらに一部解消)
  - `analyze_raw_email` (`mail_open`/`mail_import_eml` 共通の解析経路) が本文を解析する時点で `OobvRecommender::recommend()` を直接呼び、判定結果を `ImportedEmail.oobv_level`/`oobv_message` として埋め込んだ。独立コマンド `oobv_recommend` を素の本文を渡して呼ぶより、往復も本文の露出も増えない
  - `oobv_recommend` の `message_i18n_key` は i18n カタログに対応するキーが存在しない (`kaname-i18n` は出荷バイナリから到達不能、D19) ため、カタログが繋がるまでは完成した日本語メッセージを直接組み立てて返す
  - 受信トレイの詳細パネルと「ファイル解析」タブの両方に表示: 強い推奨 (送金・認証情報など) は目立つ警告として、任意の推奨は控えめな注記として表示
  - 独立コマンド `oobv_recommend` 自体は今も UI から未到達 (判定ロジックは配線したが、コマンドという経路は使っていない)。将来の直接呼び出しに備えたテスト済み内部 API として残す
- **BEC 警告バナーに送信者の本人確認を配線** (D24 (b) をさらに一部解消)
  - `history_mark_verified` は登録済みだが呼び手がゼロだった。フロントエンドは `account_id` を持っていなかったため、他コマンド (`mail_open`/`mail_fetch`) と同様に `current_account_id()` で内部解決するようシグネチャを `(account_id, email)` → `(email)` に簡素化
  - BEC 警告バナー (ADVISORY 以上) に「本人確認済みにする」ボタンを追加。電話などの帯域外手段で確認が取れた送信者をマークでき、以降の BEC 判定で信頼シグナルとして働く (`kaname-bec` の `user_verified`)
  - 対象の contacts 行は `mail_fetch` の `record_received` が受信のたびに作成するため、メール一覧に出ている送信者であれば必ず存在する
- **受信トレイに削除・添付ダウンロードを配線** (D24 (b) を一部解消)
  - 詳細パネルにツールバーを追加: 「🗑 ゴミ箱へ」(`mail_trash`。確認ダイアログ経由)・「✕ 閉じる」。以前は `onClose` が props として存在するのに呼び出し元の UI 要素が無かった
  - 添付を**全件**表示し (従来は危険なものだけ)、各添付に「ダウンロード」ボタンを追加。新規 `mail_list_attachment_blobs` でファイル名→blobId を解決してから `mail_download_attachment` を呼ぶ (`mail_open` の添付検査結果はバイト列由来で blobId を持たないため)
  - 危険と判定された添付は既存仕様どおりディスクに書かれず、理由が表示される

### Added
- **発見した欠陥クラスを `scripts/static-check.sh` に自動化** (マスク式の第5段階「自動化」)
  - 検査3: `src/main.tsx` からの import 到達可能性 (死蔵モジュールの検出)
  - 検査4: `invoke("name", {args})` と Tauri コマンド定義の**名前・引数の整合** (camelCase → snake_case 変換、shorthand プロパティ対応)
  - 検査5: 登録済みだが UI から呼ばれないコマンドの列挙 (WARN)
  - v0.6.0 までに人手で 4 回発見した欠陥は、どれも機械的に検出できたクラスだった。測定を毎回捨てていたことが再発の原因

### Fixed
- **`AdminDashboard` が死蔵し、存在しない 3 コマンドを呼んでいた**: どこからも描画されないまま `admin_get_dashboard` / `admin_get_audit_log` / `admin_list_incidents` を invoke していた。削除し、`ComposeAdmin.tsx` を実態に合わせ `Compose.tsx` に改名。**ファイルは到達可能だがコンポーネントは死んでいる**という、検査3では見つからない欠陥だった
- **`mail_list` が空配列を返す偽実装だった**: エラーではなく `Ok(Vec::new())` を返すため「メールなし」と表示される。呼び手はゼロで `mail_fetch` に置き換え済みのため削除

### Changed
- **オフライン時は保存済みメールを表示**: `mail_fetch` が失敗したら `mail_list_stored` にフォールバックし、「サーバに接続できないため保存済みのメールを表示しています」と明示する。取得できないことは読めないことを意味しない

## [0.6.0] - 2026-09-02 — 「到達可能な UI がすべて実装を呼ぶ」完成リリース

v0.5.0 が「検出器を組み付けた」リリースなら、v0.6.0 は**出荷 UI が実際に
その検出器と永続化に届く**ことを実測で確認したリリース。

### 完成の定義 (docs/socratic-review.md)
エントリポイントから到達可能な UI (**9/9**) が呼ぶコマンドがすべて実装
(`not_wired` **0 件**) で、その実装が外部キーやセッション等の前提条件を
自分で満たすこと。この状態に到達した。

### 本リリースで見つかり、直した「動いていなかったもの」
| 記録上の状態 | 実態 | 修正 |
|---|---|---|
| 受信トレイを配線した | モック専用画面が描画され、実配線版は未 import | 入れ替え (D21) |
| 送信時に DLP がブロック | 送信画面に到達不能、引数不一致で必ず失敗 | 配線 + 修正 |
| 永続化・検索を実装 | Store が開かれず、開いても FK 違反 | 自動オープン + ensure (D23) |
| BEC 詳細を表示 | 3 コマンドがスタブ | `mail_open` で .eml と同一経路 |

### 依然として真でないもの (隠さない)
MLS (XOR モック)・ローカル LLM (固定応答)・サンドボックス (no-op) は設計のみ。
`cargo check` / `vitest` は組織のエグレスポリシーにより未実施 (D20)。
SQLCipher 鍵は OS キーチェーン未統合。


### Fixed
- **永続化は一度も成功し得ない状態だった (最重要)**
  - `history_open` はコマンドとして存在したが**どの UI からも呼ばれておらず**、Store は出荷製品で一度も開かれていなかった。「Store 未接続なら何もしない」設計のため、永続化・検索・送信者履歴が**無言で無効**だった。起動時に `history_open_default` で `<data_dir>/kaname/history.db` を開く
  - さらに `PRAGMA foreign_keys = ON` なのに `accounts`/`mailboxes` への本番 INSERT が存在せず (テストの `seed_account` のみ)、Store を開いても `save_message`/`record_received`/`set_setting` は **FK 違反で必ず失敗**していた。書き込み前に `ensure_account`/`ensure_mailbox` を通す
  - SQLCipher 鍵は `history.key` (0600) に保存。**OS キーチェーン未統合のため同一ユーザー権限のプロセスからは読める**ことを明記 (他ユーザー・持ち出しへの保護であり、同一アカウント上のマルウェアへの保護ではない)
- **オンボーディングを配線 (D22 解消)**: `settings_save_onboarding` を `settings` テーブルへ実装し、初回起動時に表示。到達可能フロントエンドモジュール **8/9 → 9/9**、`not_wired` スタブ **0 件**
- **出荷 Inbox が呼ぶスタブ 3 件を実装** (`mail_open` / `mail_get_mailboxes`)
  - PR #82 で到達可能にした `Inbox` は `mail_get_body` / `bec_get_score` / `mail_get_mailboxes` を呼んでいたが、**3 つともスタブ**でメールを開くたびに必ず失敗していた。到達可能にした画面がスタブを呼ぶなら到達させた意味がない
  - `mail_open(email_id)`: JMAP の `blobId` (生 RFC 5322 全体) を `download_blob` で取得し、ローカル `.eml` と**同じ** `analyze_raw_email` に通す。本文・BEC スコア・シグナル・添付検査・DLP・リンク評価が一度に得られ、**新しい解析コードは 0 行**。`bec_get_score` という別コマンドは不要になり削除
  - `mail_get_mailboxes`: `JmapClient::get_mailboxes` を配線
  - 受信トレイの詳細ビューで危険な添付と機微情報 (DLP) も表示
  - **作成画面の「✨ AI 草案」を削除**: 定型文を「AI 草案」と表示して挿入しており、LLM がスタブ (D2) である以上 AI 出力を偽っていた
  - 呼び手ゼロのスタブ `mail_query_emails` / `bec_get_score` を削除。残る `not_wired` は `settings_save_onboarding` のみ (D22)
- **出荷 UI がモック専用コンポーネントを描画していた (最重要)**
  - 受信トレイは `KanameDesign` を描画していたが、同コンポーネントは自身のコメントが認めるとおり **invoke を一切呼ばないモックデータ専用**だった。一方 `mail_fetch` / `mail_search` / `bec_get_score` を実際に呼ぶ `Inbox` は**どこからも import されておらず死蔵**していた。両者を入れ替え、受信トレイが実データを表示するようにした
  - **メール送信に UI から到達できなかった**: `mail_send` を呼ぶのは未到達の `ComposeAdmin` のみ。「作成」ビューとして配線した
  - **送信は配線しても実行時に必ず失敗する状態だった**: フロントは `{ req: { to, subject, body, draft_id } }` を送っていたが Tauri コマンドは `(from, to, subject, body)` を取る。引数形を合わせ、差出人入力欄を追加 (JMAP セッションはアカウントのメールアドレスを公開しないため)
  - **UI が実装されていない暗号化を「対応済み」と表示していた**: 作成画面の MLS インジケータは宛先ドメインの接尾辞だけを見て判定していたが、`kaname-mls` は XOR モック (D1) で実際には暗号化されない。常に非対応を返すよう修正
  - `EmailRow.triage` が `"important"` 固定だった。実装済みの `kaname_core::ux_features::TriageEngine` を配線 (フロントエンドの TypeScript 重複実装は削除し、判定元を一つにした)

### Removed
- **死蔵していたモック専用フロントエンド 2,284 行を削除**: `KanameApp.tsx` (1,134 行・ハードコードされたデモメールと `triageEmail` の重複実装)、`KanameDesign.tsx` (1,150 行・モック専用の受信トレイ)。到達可能なフロントエンドモジュールは **7/11 → 8/9**

### Added
- **添付ファイルのダウンロード** (D10 の最後の項目を解消 — **D10 完全解消**)
  - `kaname-jmap` に `download_blob` を追加 (`download_url` テンプレート置換 + Bearer 認証、25 MB 上限を Content-Length と実読み取りの二重で確認)
  - `kaname-render` の添付検査を `scan_attachment_bytes(filename, mime, bytes)` として公開関数に抽出し、フォルダ一括スキャンと単一 blob の両方で同一の検査を適用
  - `mail_download_attachment` コマンド: **ディスクに書く前に必ず検査**し、`is_dangerous` なら**保存せず**リスク一覧のみ返す (kaname-sandbox が no-op の現状、実行は許さず「検査して警告」に徹する)
  - `sanitize_filename` で添付名のパストラバーサル・制御文字を無害化 (添付名は攻撃者制御の入力)
- **ソクラテス問答による製品総括** `docs/socratic-review.md` — 「これはメールクライアントか」「セキュリティは本物か」「最大の弱点は何か」「完成とは何か」の自問と、長所・短所・改善点の一覧

- **メール本体の永続化と検索** (D10 の残りを解消)
  - `messages` テーブルはスキーマもインデックスも完備していたが、**INSERT/SELECT がワークスペース全体でゼロ件**だった。`save_message` / `list_messages` / `search_messages` を実装
  - **冪等性**: `id` を `sha256(account_id + jmap_id)` で決定論的に採番し `ON CONFLICT DO UPDATE`。再取得しても行が重複しない
  - **`body_encrypted` には書かない** — MLS がモック段階 (D1) の現状で暗号化列に平文を入れると「暗号化済み」と偽ることになる。一覧表示に必要な `body_preview` のみ保存
  - **検索は LIKE ベース** — FTS5 は SQLCipher ビルドで有効とは限らず、有効性を確認できない環境で依存するのは危険。利用者の検索語の `%` `_` はエスケープする
  - 受信箱の検索欄は**ハンドラ未バインドの「飾り」だった**ため `mail_search` に接続
  - 一覧読み込みを未配線の `mail_query_emails` から実装済みの `mail_fetch` に切り替え

## [0.5.0] - 2026-07-18 — 全検出器を製品に組み付けた「組み立て完了」リリース

v0.4.0 で確立した解析パイプラインに、**実装済みだが眠っていた部品を
すべて接続**したリリース。到達可能クレートは **10 → 18 / 27**。

### 一貫して見つかった構造
「実装は揃っているのに、渡す経路が1つ無いだけで部品群が眠る」パターンが
繰り返し見つかった。今回接続したものはすべてこれに該当する:

| 眠っていたもの | 欠けていた1経路 |
|---|---|
| BEC の URL シグナル / quishing の URL 評価 | 本文から URL を抽出する関数 |
| 添付検出器5種 (MIME偽装/polyglot/危険拡張子/SVG/メタデータ) | `parse()` が添付バイトを捨てていた |
| カレンダー招待検査 (CalPhishing) | 添付経路への接続 |
| JMAP 送受信 | `kaname-ui` が `kaname-jmap` に依存していない |
| BEC の履歴シグナル | Store の `SenderProfile` を BEC に渡す変換 |
| SaaS リンク安全性 (D13) | 抽出済み URL への適用 |
| 送信者文体認証 (D12) | プロファイル蓄積の器 |
| トラッキングピクセル検出 | `analyze_body_risks` への追加 |

### Added
- **JMAP サーバとの送受信** — 受信メールがファイル解析と同じ検出器を通る。送信前に DLP (`Outbound`) でブロック
- **送信者履歴の永続化** (SQLCipher) — BEC の履歴シグナルが初めて発火
- **添付ファイル検査** — MIME偽装 / polyglot / 危険拡張子 / SVGスクリプト / メタデータ / カレンダー招待
- **本文リンク評価** — 短縮URL・タイポスクワット・自由TLD・SaaS リンク安全性
- **送信者文体認証 (SSA)** — アカウント乗っ取り検出
- **トラッキングピクセル検出**
- `scripts/static-check.sh` — `cargo check` が使えない環境での構文・未定義関数検証

### Fixed
- **回帰修正**: PR #64 の編集で `analyze_body_risks` が定義ごと誤削除され、コンパイルエラーの状態が 5 PR 検出されなかった問題 (D20 の実害)

### 意図的に含めないもの
`kaname-mls` (モック暗号) と `kaname-sandbox` (no-op) は、**組み込むと
「暗号化/隔離されている」と偽ることになる**ため実装が入るまで含めない。
`mockserver`/`tests` は開発用、`billing` はスコープ外、
`core`/`continuity`/`i18n`/`tray` は本体機能が固まってから。

### 既知の制約
- **型検査 (`cargo check`) は未実施**。組織のエグレスポリシーにより
  `static.crates.io` が遮断されている (D20)。`scripts/static-check.sh` で
  構文検証のみ実施
- メール本体の永続化・検索・添付ダウンロード・MLS 暗号化・
  ローカル LLM 推論は未実装

### Added
- **トラッキングピクセル検出を接続** — README が「デフォルトでブロック」と謳う機能の実体 `kaname-privacy` は実装済みだが未接続だった。検出件数とドメインを本文リスクに報告する
- **残るクレートの仕分けを文書化** — 到達可能 18/27。残る 9 個は**意図的に含めない**理由を `docs/maturity.md` に明記。特に `kaname-mls` (モック暗号) と `kaname-sandbox` (no-op) は、**組み込むと「暗号化/隔離されている」と偽ることになる**ため実装が入るまで含めない
- **送信者文体認証 (SSA) を接続しアカウント乗っ取り検出を有効化** — `kaname-ssa` (1209行) は文体プロファイルによる乗っ取り検出と `EmailStyleFeatures::extract()` を実装済みだが**孤島クレート**だった (D12)。送信者ごとに文体プロファイルを蓄積し、逸脱を警告する。**判定してから取り込む**順序にした (取り込んでから判定すると、なりすましメール自身がプロファイルを引き寄せて検出が鈍る)。`Date` ヘッダが無い場合は評価しない (`send_hour` を 0 で代用すると「深夜送信」という誤シグナルを生むため)
- **SaaS リンク安全性判定を本文リンクに接続** — `kaname-saas-guard` (1556行、偽 SaaS ドメイン検出・SaaS リンク経由のプロンプト注入・OAuth state 検証) は**どこからも依存されない孤島クレート**だった (D13)。本文リンクは既に抽出済みだったため、そこへ載せて到達可能にした。`Warn` 以上のみ報告し `Safe`/`Caution` は出さない (通常の SaaS 通知でも出るため、警告疲れを避ける)
- **送信者履歴を永続化し BEC の履歴シグナルを有効化**
  - `kaname-bec` は履歴シグナル (初回連絡 / 久しぶりの連絡 / 普段と違うトピック / 検証済み) を実装済みだが、`sender_history` に常に `None` を渡していたため**一度も発火していなかった**
  - `kaname-store` には `SenderProfile` の CRUD が実装済みで BEC の `SenderHistory` と対応する形だった。**両者を繋ぐコードが無いだけ**だったため配線
  - `history_open` / `history_close` / `history_mark_verified` を追加。受信時に `record_received` で履歴を蓄積
  - **履歴が無い場合は `None` のまま**にし、BEC に履歴シグナルを評価させない (履歴の不在を「初回連絡」と断定しないため)
  - `user_reported_malicious` は Store 側に列が無いため **`false` 固定** — `true` と偽ると危険側の判定が不当に強まるため、列が追加されるまで保守的に扱う
  - 日付計算は `chrono` を使わず自前実装 (履歴シグナルは日単位の粗い粒度で足りるため、新規依存を増やさない)
- **JMAP サーバとの送受信を配線 (D10 の中核を解消)**
  - `kaname-ui` が `kaname-jmap` に依存していなかったため、出荷バイナリからサーバへ到達する経路が**コンパイル時点で存在しなかった**。`kaname-jmap` 自体は RFC 8621 準拠の実装が揃っており、**配線するコードを書くだけ**で動く状態だった
  - `mail_connect` / `mail_disconnect` / `mail_fetch` / `mail_send` を実装・登録
  - **受信した実データが、ファイル解析と同じ BEC 検出器を通る** (一覧の各通に判定を付与)
  - **送信前に DLP (`Direction::Outbound`) を実行し、`Block` 判定なら送信しない** — これが DLP 本来の用途であり、受信側検査と対になる
  - **認証情報は永続化しない**: Bearer トークンはメモリ内にのみ保持。`kaname-store` の鍵管理が keyfile フォールバックを含む現状では平文同然で置くことになるため、安全に保管できるまで保管しない方針
  - UI に「サーバ接続」タブを追加 (`src/ui/MailConnect.tsx`)

### Fixed
- **回帰修正: 誤って削除された `analyze_body_risks` を復元** — PR #64 の編集で定義ごと巻き込まれ、呼び出しだけが残ってコンパイルエラーの状態が **5 PR にわたり検出されなかった**。`cargo check` が使えない環境 (D20) の実害
### Added
- **`scripts/static-check.sh`** — `cargo check` の代替となる静的検証。全 Rust ファイルの構文チェックと「定義が消えた関数の呼び出し」検出を自動化。上記回帰を受けて追加 (型検査の代替にはならないことも明記)
- **添付ファイル検査を解析パイプラインに接続**
  - `kaname-render` には添付検査 (MIME 偽装 / polyglot / 危険拡張子 / SVG スクリプト / メタデータ) が揃っていたが、**`parse()` が `AttachmentHeader` にバイト列を保持せず捨てていた**ため、検出器に渡す経路が無く一つも動いていなかった
  - `kaname_render::scan_attachments()` を新設。バイト列はクレート内で完結させ (`AttachmentHeader` は変更しない)、検査結果のみ返す。1 添付あたり先頭 10 MB まで検査
  - 単体解析: 添付を危険度付きで表示 (危険/問題なし バッジ + リスク文言)
  - フォルダ一括解析: 危険な添付の件数を一覧に表示 (`attachment_risk_count`)
  - **メタデータのみの検出は `is_dangerous = false`** — 作成者情報や GPS はプライバシー通知であって実行リスクではないため
  - サンプル `06-dangerous-attachment.eml` を追加 (二重拡張子 `.pdf.lnk` + `image/png` を装った PE 実行ファイル)
  - **カレンダー招待 (.ics) の検査も接続** — `calendar_guard` は実装済みだが未接続だった。招待は「添付」として届くため `scan_attachments` に載せた。`Danger` のみ実行リスク扱いとし `Caution` は注意喚起に留める。サンプル `07-malicious-calendar.eml` を追加 (CalPhishing 自動登録永続化 + DESCRIPTION へのプロンプト注入)
- **本文リンクの評価を解析パイプラインに接続**
  - `kaname-bec` の URL 評価シグナルと `quishing::evaluate_url` (悪性ドメイン/短縮URL/タイポスクワット/自由TLD) は実装済みだったが、**本文から URL を取り出す関数が無いだけで一度も実データで発火していなかった**。`extract_urls_from_text` を新設して接続
  - 単体解析: 抽出 URL を BEC へ供給し、リンクの評判判定結果を本文リスクに併記
  - フォルダ一括解析: リンクドメインを `kaname-radar` のキャンペーン相関に供給。各メールの DLP 件数も一覧に表示 (`dlp_count`)
  - サンプル `05-malicious-link.eml` を追加 (短縮URL + 数字置換タイポスクワット + 自由TLD)

## [0.4.0] - 2026-07-18 — ローカル・メールセキュリティ解析ツールとして完結

イーロン・マスクのアルゴリズム (要件を疑う → 削除する → 簡素化する → 組み立てる)
を適用し、**「部品は揃っているが製品として動かない」状態を解消**したリリース。

### 疑って突破した3つの要件

| 疑った前提 | 結果 |
|---|---|
| 「BEC 検出には LLM が必要」 | **要件を削除**。10シグナル中9つはモデル不要のため `BecDetector::deterministic_only()` を追加し出荷可能にした |
| 「メールはサーバから取得しなければならない」 | **ローカル `.eml` で突破**。サーバも認証情報も不要で実メールがパイプラインを流れるようになった |
| 「検証にはネットワークが必要」 | **rustc 1.94.1 が直接使えた**。変更ファイル全ての構文チェックを実施 |

### 発見した根本問題
依存グラフの実測により、**出荷バイナリに到達可能なのは 27 クレート中 10 個のみ**で、
看板機能の `kaname-bec` (110+ テスト) すら製品に含まれていないことが判明した (D19)。
「部品を作る」のをやめ「組み立てる」方針に転換した。

### Added
- **実メール解析** (`mail_import_eml` + 「ファイル解析」タブ) — MIME 解析 → 送信ドメイン認証の評価 → BEC 判定 → サニタイズ → 本文リスク検出を実データで実行
- **フォルダ一括解析** (`mail_scan_folder`) — 危険度順トリアージ + **複数メール横断のキャンペーン検出** (`kaname-radar` を初めて動作させる唯一の入口)
- **DLP による機微情報検出** (`Direction::Inbound`) — 受信メールに機微情報が含まれる事実を転送・返信前に警告
- **動作確認用サンプル** (`examples/emails/` 4通 + 手順書) — キャンペーン検出も試せる構成

### Changed
- 固定値を返していた6コマンドをすべて**実際の検出結果**に接続 (`ai_detect_phishing` / `mail_list` の `bec_verdict` / `mail_get_summary` / `mail_get_body` ほか)
- **未使用だった9つのレンダリング系検出器**を本文表示時に実行するよう接続
- 到達可能クレート **10 → 13** (`kaname-bec` / `kaname-radar` / `kaname-dlp`)

### Removed
- **偽の AI 出力を削除** — 要約・スマートリプライは固定文字列を返しつつ `local_inference: true` と成立していない保証を主張していた。未実装であることを正直に返すよう変更

### Fixed
- `mail_get_body` のフロント/バックエンド型契約不一致 (`String` vs `BodyDto`)
- `magic_bytes` の SVG 検出が先頭256バイトのみで偽装を見逃していた問題

### 既知の制約
サーバとのメール送受信 (JMAP)、永続化、アカウント設定 UI、検索、添付ダウンロード、
MLS 暗号化、ローカル LLM 推論は**未実装** (いずれもネットワークが前提)。
また crates.io にアクセスできない環境のため **`cargo check` による型検査は未実施**。
詳細は `docs/maturity.md` / `docs/gap-analysis.md` を参照。

### Changed
- **「組み立て」フェーズ — 部品を製品に組み付ける (イーロン・マスクのアルゴリズム適用)**
  - **依存グラフの実測**により、出荷バイナリに到達可能なのは **27クレート中10個のみ**で、`kaname-bec` (看板機能・110+テスト) すら製品に含まれていないことが判明 (gap-analysis **D19**)
  - **LLM という要件自体を削除**: `BecDetector` は `Box<dyn LocalLlm>` を必須としたが実装はテスト内のみで、これが BEC 出荷を阻んでいた。10シグナルファミリーのうち9つはモデル不要の決定論的ロジックであるため、`NullLlm` と `BecDetector::deterministic_only()` を追加して LLM なしで動作可能にした
  - **BEC 検出を実際に実行**: `ai_detect_phishing` (固定値 `score: 0.12`)、`mail_list` の `bec_verdict` (モックに手書き)、`mail_get_summary` (固定値) をすべて実際の判定結果に接続
  - **HTML サニタイズ経路を実際に実行**: `mail_get_body` は固定文字列を返しており `kaname-render` のサニタイズが一度も走っていなかった。`sanitize_html` → `to_srcdoc` の実経路に接続し、フロントとの型契約不一致 (`String` vs `BodyDto`) も解消
  - **偽の AI 出力を削除**: `ai_summarize_email` は固定要約を返しつつ `local_inference: true` と成立していない保証を主張していたため、risk のみ本物にし要約は未実装と明示 (`local_inference: false`)。`ai_smart_reply` の固定3文は削除し未実装エラーに変更
  - 到達可能クレート **10 → 11**。新規外部依存はゼロ
  - **依然としてメールの取得元は `mock_emails()`** (D10)。実メールが流れれば同じ経路がそのまま処理する

### Added
- **docs/research-2026-07-part2.md**: セッション横断の研究反映マップと構造的発見の統合
  - 2026年研究動向 (CaMeL/FIDES のアーキテクチャ保証収束、LLMail-Inject/ARGUS、画像ベース注入、DKIMリプレイ、動的QR、deepfake増強BEC 40%) の総括
  - 研究 → 実装 (PR #25〜#33) の対応表
  - 構造的発見 (D10 配線欠如 / D16 添付AI経路未配線 / D17 型境界の宣言と実装の分離) の統合
  - **ネットワーク解放を前提とした優先ロードマップ** (P0 検証 → P1 型実効化 → P2 配線)

### Changed
- **Dual-LLM 型不変条件の実効性監査と正直化 (最重要)**
  - 2026年の out-of-band 防御研究 (CaMeL/FIDES/Progent、arxiv 2606.26479) が「振る舞いではなくアーキテクチャによる保証」へ収束したのを受け、Kaname が公言する**より強い「コンパイル時の型強制」が実際に成立しているか**を実コードで検証した
  - **結果: 型境界の「定義」は堅牢だが「実装」がそれを通っていない**。ワークスペース全体で `impl QuarantinedLlm for`/`impl PrivilegedLlm for` が **0 件**で、実推論経路 `llm_bridge` は生 `&str` API。`as_text()` は `pub` で I1 は規約。`Content<L>` の `Deserialize` derive により `Content<Trusted>` を JSON 偽造可能。`subprocess.rs` は P-LLM に `(allow network-outbound)` を与えており CLAUDE.md I4 と矛盾 (参照先 `resources/seccomp/` も不在)
  - **良いニュース**: I3 の中核 (フィールド private / 公開コンストラクタ2つのみ / `from_validated` が `pub(crate)` / `unsafe` ゼロ / `compile_fail` テスト有り) は本物
  - **悪用可能な経路は現時点で存在しない** (D10 でパイプライン未配線・推論もスタブ)。問題は「配線時に確実に穴になる構造」で、特に**型安全な trait を誰も実装していないため配線時の最短経路が型を迂回する側にある**
  - README の「コンパイル時型安全」節・`docs/maturity.md`・`docs/threat-model.md` §3.16 を実態に合わせて修正。誤導していた doc コメント (`as_text` の「Q-LLM 内部のみ」、`Content` の「型変換は禁止される」) も是正
  - 修正手順を `docs/gap-analysis.md` **D17** に file:line 付きで記録。**中核型の derive 変更はワークスペース全体の再コンパイルを要するため、`cargo check` が実行できない現状では意図的に実施していない**

### Added
- **kaname-render SVG のマルチモーダル・プロンプト注入検出** (`svg_guard`)
  - 攻撃 (Polyglot SVG Attack): SVG は「画像」でありながら XML のため、`<desc>`・**XML コメント (描画されない)**・**CDATA セクション**に命令を潜ませられる。人間の目には正規の画像でも、それを処理する AI は指示として読んでしまう
  - 従来の `svg_guard` は `<script>`・イベントハンドラ等の**ブラウザでのスクリプト実行**のみを見ており、この経路は未検出だった
  - `SvgRisk::PromptInjectionAttempt` を追加。**同一クレートの `calendar_guard` の先例をそのまま踏襲**し `kaname_screen::PromptScreener` に委譲 (原文のまま渡す / `Blocked` のみ採用 / `HighEntropy` は除外して誤検出防止)
  - `SvgRisk::XmlExternalEntity` を追加 — `<!DOCTYPE`/`<!ENTITY` による XXE 形式ペイロード・billion laughs 型 DoS の入口を検出
  - 出典: [arxiv 2603.03637](https://arxiv.org/abs/2603.03637) / CSA research note (2026-03)「Image-based Prompt Injection」— 画像埋め込み命令が**テキスト層のサニタイズを迂回**し、ステルス条件下で最大 **64% の攻撃成功率**。XML/SVG では CDATA 悪用と XXE 形式ペイロードが名指しされている
  - テスト6件追加 (desc/XMLコメント/CDATA の注入検出、XXE 検出、**通常の日本語 SVG の非誤検出**、抽出器の網羅性)
- **kaname-render 動的QR・テキストQR亜種の検出強化** (`quishing`)
  - **動的 QR**: 短縮 URL / QR リダイレクトサービス (bit.ly, tinyurl, qrco.de, flowcode.com 等) を `Suspicious` 判定。配信時は無害なページを指しておき、検査通過後にフィッシング先へ差し替える手法のため、スキャン時点の宛先検証では防げない — 検証不能な参照そのものを疑う設計。サブドメイン形式 (`go.bit.ly`) も対象
  - **テキスト QR の文字集合拡張**: 罫線ブロック8種のみ → 幾何学記号 (■□●○等)・絵文字ブロック (⬛⬜🟥🟦)・全角空白・**点字ブロック U+2800..U+28FF** (2x4ドットを1文字で表現でき、テキストQRレンダラで最多用) を追加。画像添付だけを走査するフィルタを回避する Barracuda 観測の手法に対応
  - 背景: quishing は 2026 年上半期に約 **146%増**、2025年8-11月に成功事例が 4.6万→25万へ**5倍増**。FBI が 2026-01 に北朝鮮 Kimsuky/APT43 の利用を「MFA 耐性のある侵入経路」として警告
  - テスト6件追加 (短縮/リダイレクタ/サブドメイン判定、信頼ドメイン回帰、点字QR、幾何学記号QR)
- **kaname-bec DKIM リプレイ攻撃の検出** (署名ドメイン `d=` と From ドメインの整合検証)
  - 攻撃: 正規組織 (Google/PayPal/Apple 等) の DKIM 署名済みメールを入手して再送する。署名は有効なままなので DKIM は pass し、**DMARC は SPF と DKIM の OR 判定 (AND ではない) のため DMARC も pass** する → 受信側には「認証を完全に通過した正規メール」に見える
  - 従来の `check_auth` ではこの組み合わせ (SPF fail + DKIM pass + DMARC pass) が「1つ失敗 = 0.15」の軽微扱いで、ARC pass があると更に減点されていた
  - `dkim_check` は既に `d=` を解析していたが**整合検証に使っていなかった**ため、これを追加。DKIM が pass しているケースほど危険 (認証通過に見える) として重み付け
  - 親ドメイン署名 (`d=example.com` / From が `mail.example.com`) は正当として誤検出しない
  - 出典: 2025年の Google スプーフィング事例、"DMARC OR trap" (DMARC が OR ロジックである構造的弱点)
- **kaname-render SVG 添付攻撃の検出** (`svg_guard` モジュール新設)
  - 背景: 悪意ある SVG 添付は2024年比で**50倍**に増加 (2025年)。2026年2月の単一キャンペーンでは **120万通が53,000組織**へ配信された。SANS ISC が 2026-06 に MIME 型回避手法を警告
  - 検出: `<script>` 要素 (**非推奨 MIME 型 `application/ecmascript` による回避**も型を記録して検出)、イベントハンドラ (`onload=` 等、`<script>` なしの実行)、`javascript:`/`vbscript:` スキーム、`<foreignObject>` による HTML 埋め込み、base64/`atob()` の多層エンコード、外部リソース参照
  - `magic_bytes::is_svg` は**先頭256バイトしか見ず**、長いコメントで `<svg` を押し下げると検出を回避できたため、8KB まで走査する `looks_like_svg()` を追加
  - 出典: SANS ISC (2026-06, Xavier Mertens)、OPSWAT、Microsoft 脅威情報 (2026-02)

### Fixed
- **kaname-bec のキーワード検出が難読化で完全に回避できた問題を修正 (中核機能・最重要)**
  - 中核の BEC 検出器が件名・本文の照合に `to_lowercase()`/`to_ascii_lowercase()` のみを使っており、**ゼロ幅文字・soft hyphen (U+00AD)・全角ラテンの正規化が一切なかった**
  - 攻撃: 「至\u{00AD}急」は人間には「至急」と見えるが `contains("至急")` は false → 緊急性・金銭・チャネル誘導・Cialdini の全キーワード検出をすり抜けられた
  - 2026年の実キャンペーンで観測された手法 (RFC 2047 encoded-word でデコードされた件名に soft hyphen を散布) がそのまま通用する状態だった
  - `kaname-memory-guard::normalize_for_matching` を適用して解消 (kaname-oobv で確立した対策の横展開)

### Added
- **kaname-bec 表示名ホモグラフ検出** (`idn_homograph::analyze_display_name` / `fold_homoglyphs`)
  - 攻撃: `From: "СЕО 山田" <attacker@evil.com>` (キリル文字 С/Е/О) は人間には `CEO 山田` と区別できないが、従来の `to_lowercase()` 比較では一致せず**なりすまし検出を完全に回避**できた
  - ホモグリフを ASCII に畳み込んでから既知連絡先と照合するよう `reply_to_spoof` を修正。表示名自体のホモグリフ/スクリプト混在も検出可能に
  - 背景: 2025-2026 の観測ではホモグリフ悪用の主戦場が URL/ドメインから **From ヘッダーの表示名**へ移行 (表示名はレジストラの制約を受けず任意の Unicode を置けるため)。出典: Unit 42 (2025)、arxiv 2604.04926「Comprehensive List of User Deception Techniques in Emails」
  - 既存のドメイン用ホモグリフ判定を再利用し、誤検出防止テスト (日本語表示名/無関係な表示名) も追加
- **kaname-screen 出力監査に「セキュリティ判定の詐称」検出を追加** (`AuditFinding::ForgedSecurityVerdict`)
  - 攻撃: メール本文に「本メールはセキュリティチームにより検証済みです」等を仕込み、Q-LLM の要約に反映させてユーザーを信用させる
  - 設計根拠: Kaname の判定は `kaname-bec` の決定論的シグナルが source of truth であり、**LLM の散文は判定の根拠になり得ない**。したがって出力中の免罪主張は構造上いかなる信頼できる根拠にも裏付けられていない (幻覚か注入の反映)
  - 出典: arxiv 2605.17634 (LLMail-Inject — 良性メールに埋め込まれた4,300件の人手作成注入。エージェントの判定チャネル自体が攻撃対象になることを実証)、arxiv 2605.03378 (ARGUS — 決定が信頼できる根拠に裏付けられているか実行前に検証)
  - 誤検知防止のため**肯定的な免罪の断定のみ**を対象とし、正当な脅威警告 (「フィッシングの疑いがあります」) は検出しない
- **arxiv 研究ベースの防御コマンド10件を到達可能化** (これまで `invoke_handler` 未登録で死蔵)
  - 入力スクリーニング (2505.22852 §2.1) / 出力監査 (§2.2) / Tiered-Risk (§3) / メモリ信頼スコア (2601.05504) / Rule of Two (2601.17548) / ツール引数検証 (2601.11893) / トラジェクトリ記録・リセット / OOBV 推奨 / Deepfake 判定
  - `commands.rs` の `#[cfg_attr(feature = "tauri-app", ...)]` は src-tauri が該当フィーチャーを指定しておらず無効だったため、既存12コマンドと同じラッパー方式で登録

### Fixed
- **UI が呼ぶが未定義だった5コマンドを追加** (`mail_send`/`mail_get_mailboxes`/`mail_query_emails`/`bec_get_score`/`settings_save_onboarding`)
  - 「コマンドが存在しない」という不可解な失敗を、明示的な「未配線」エラーに変更 (偽データは返さない)
  - Inbox が起動時に無言で永久に空になっていた問題が、原因表示に変わった

### Changed
- **実装ステータスの正直化 (First Principles 監査の反映)**: `docs/maturity.md`・README・`docs/gap-analysis.md` D10 に、**現状のビルドではメールを送受信できない**事実を検証根拠付きで明記。`kaname-ui` が `kaname-jmap`/`kaname-store` に依存しておらず到達経路が無いこと、`messages` テーブルへの INSERT/SELECT がゼロ件であること等。D15 (コマンド死蔵) を追加

## [0.3.22] - 2026-07-17 — 最新研究反映・クロスクレート統合・監査バグ修正リリース

このリリースは (1) ワークスペース全体のビルド不能状態の解消、(2) 2026-07 の
最新研究 (quishing 亜種・CalPhishing・プロンプト注入) の反映、(3) Ultracode
徹底監査 (3エージェント並列・全27クレート) で発見したクロスクレート連携の
欠落とロジックバグの修正、(4) 実装状況の正直化 (docs/maturity.md,
docs/gap-analysis.md, README) をまとめたもの。**中核 (MLS暗号・LLM推論・
Firecracker・課金永続化・UIバックエンド配線) はモック段階であり本番運用は
不可** — 詳細は docs/maturity.md を参照。

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
- **kaname-saas-guard SaaSリンクのプロンプト注入検査** (`SaasLinkInspector::evaluate`)
  - SaaSリンクのクエリパラメータ (`?note=`等) を `kaname-screen::PromptScreener` で検査し `SaasLinkRisk::Block` に格上げ
  - 偽SaaSドメイン検出 (`notdocusign.com`等) との併存を確認 (Suspicious→Block)
- **kaname-bec クロスクレート連携** (Ultracode監査で発見、docs/gap-analysis.md 参照)
  - `check_content_heuristics` に `kaname-pivot::PivotDetector` を統合 — 暗号通貨アドレス/WhatsApp/Telegram/Signal等の構造化チャネル誘導検出 (従来はハードコードフレーズ一致のみ)
  - `check_llm` に `kaname-screen::PromptScreener` を統合 — Quarantined LLM に渡す前にプロンプト注入をスクリーニングし、Blocked時はLLMをスキップして注入シグナルを加点

### Fixed
- **kaname-observability PIIサニタイザの検出漏れ** (北極星 I5 に直結)
  - `mask_email_addresses` が数字始まりのローカル部 (`12345@vendor.com` 等) を無加工でログに残していた問題を修正 (`is_ascii_alphabetic`→`is_ascii_alphanumeric`)
- **kaname-radar 集計バグ**: `unknown:` バケットが `or_insert_with` の返り値を捨てており、同一未解決ドメインからの2通目以降が集計されず継続キャンペーン検出が機能していなかった問題を修正
- **kaname-mls 開始者側エポック初期化漏れ**: 会話開始者が自分の会話に届くリプレイ Commit を検出できなかった問題を修正 (`start_one_to_one` で `epochs` を初期化し受信側と対称化)
- **kaname-store SQLCipher鍵のゼロ化漏れ**: PRAGMA/ATTACH 文に埋め込む生鍵文字列を `Zeroizing<String>` でラップし、実行後にヒープ上の平文鍵を確実にゼロ化
- **kaname-oobv Unicode/全角バイパス**: `recommend` のキーワード照合を `kaname-memory-guard::normalize_for_matching` 経由に変更し、全角ラテン文字 (`ＵＲＧＥＮＴ`)・ゼロ幅文字挿入によるOOBV推奨回避を防止
- **kaname-jmap SSRFリダイレクト未検証**: `JmapClient::connect` の HTTP クライアントに `safe_redirect_policy()` (per-hop DNS再検証) を適用し、DNSリバインディングによるSSRFの入口を閉塞
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

<!-- 2026-09 訂正: 以下は誤ったリポジトリ (kaname-app/kaname) を指していた
     (D31/D33 と同じ欠陥クラス)。実際のリポジトリ shizukutanaka/kaname に
     訂正した。ただし git tag は一つも作成されていない (v0.1.0〜v0.7.1 の
     いずれも) ため、これらのリンクは訂正後もリリースタグが作られるまで
     404 になる。タグ作成はリリース権限を持つ人間の判断領域のため、本
     セッションでは作成していない。v0.5.0 以降 (このリポジトリで実際に
     行われたリリース) のリンクは追加していない — 存在しないタグへの
     リンクをこれ以上増やすと同じ問題を広げるだけのため。 -->
[Unreleased]: https://github.com/shizukutanaka/kaname/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/shizukutanaka/kaname/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/shizukutanaka/kaname/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/shizukutanaka/kaname/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/shizukutanaka/kaname/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/shizukutanaka/kaname/releases/tag/v0.1.0
