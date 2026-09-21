# docs/threat-model.md — Kaname Threat Model

Version 1.0 · 2026-04-18 · Owner: QSM (Quality & Security Manager)

**Review cadence**: Quarterly, plus whenever a new attack class is published or an ADR affecting security lands.

This is our contract with ourselves about what we defend against, what we accept as residual risk, and how we know each control is holding.

---

## 1. Scope and assumptions

### 1.1 Assets we protect, ranked
1. Message body and attachment content (current and historical)
2. Cryptographic private keys (E2E, signing, transport)
3. User credentials and auth tokens
4. Contact graph and correspondence metadata
5. Configuration and policy data
6. Aggregate availability of the service to the organization

### 1.2 Users we care about
- Primary: employees of organizations that purchased Kaname (Business / Pro / Enterprise).
- Secondary: admin users with privileged configuration access.
- Tertiary: external senders whose mail is received (their content is an input we treat as untrusted; we do not owe them confidentiality of our defensive decisions).

### 1.3 Threat actor capability bands

| Band | Examples | Resources | We defend |
|---|---|---|---|
| Opportunist | phishing kit buyer, drive-by | low | Yes — full defense |
| Organized criminal | BEC rings, ransomware gangs | medium | Yes — full defense |
| APT / nation-state | intelligence services | high; 0-days; supply chain access | Yes — best effort; some threats only mitigated, not eliminated |
| Insider | disgruntled employee, compromised admin | privileged access to one endpoint | Partial — see §6 |
| Physical attacker with device | evil-maid, border seizure | device physical access | Full at-rest protection (SE/TPM); limited if device unlocked |

We **out-of-scope**: threats from the operating system kernel being malicious (we trust the OS), threats requiring physical disassembly of Secure Enclave, quantum attacks from hypothetical future hardware against ML-KEM **combined with** X25519 (hybrid means both would need to break).

---

## 2. STRIDE — classical threat axes

> **実装状況の凡例**: 下表の Control 列は実装済みの対策と設計意図 (未実装) が混在していた。実測と照合し、未実装の対策には *(設計意図・未実装)* を明示した (D158)。

### 2.1 Spoofing

| Threat | Example | Control |
|---|---|---|
| Display-name spoofing | Sender shows "CEO" but address is attacker@evil.com | UI always shows full address; display-name-only rendering forbidden |
| Homoglyph domain | mitsui-g1obal.co.jp (l→1) | Punycode expansion + Levenshtein distance from user's contacts |
| BEC (business email compromise) | Fake vendor requesting wire transfer | Multi-signal local LLM scoring; hard-block on score ≥ threshold |
| DKIM/SPF/DMARC fail | Any of the three fails | UI red banner; AI pipeline refuses to summarize |
| MLS identity spoofing | Attacker forges a Kaname identity | Out-of-band verification UI for first-contact + safety-number 照合 (D122 リプレイ帳簿)。署名鍵の実保管は `mls.db` (SQLCipher) + `<data_dir>/kaname/mls.key` の 0600 ファイル — Secure Enclave/Keychain 統合は**未実装** |

### 2.2 Tampering

| Threat | Example | Control |
|---|---|---|
| MITM on transport | Downgraded TLS, stripped STARTTLS | JMAP クライアントは HTTPS/TLS のみ (cleartext fallback なし)。MTA-STS/DANE/TLSA の強制は受信経路ではなくサーバ側設定であり本クライアントの実装範囲外 *(設計意図・未実装)* |
| In-transit body modification | Malicious relay mutates content | DKIM verification + (for Kaname-to-Kaname) MLS AEAD |
| At-rest DB tampering | Attacker with disk access modifies SQLite | SQLCipher (bundled-sqlcipher; D75 で実効化。鍵は `<data_dir>/kaname/history.key` の 0600 ファイル — SE/Keychain 統合は未実装); tamper-evident hash chain over critical records |
| Supply-chain code injection | Compromised dependency ships malware | `deny.toml` + release 時の `cargo audit`/`cargo-deny` (scripts/release.sh)。SBOM・cargo-vet・再現ビルド・Ed25519+ML-DSA 署名付き更新チャネルは *(設計意図・未実装)* |

### 2.3 Repudiation

| Threat | Example | Control |
|---|---|---|
| Sender denies sending | Business dispute | For Kaname-to-Kaname: MLS authenticated sender; for classic mail: DKIM signature captured and archived |
| Admin action denied | Admin denies having changed policy | 監査ログの SHA-256 ハッシュチェーンは実装済み (kaname-store、BEFORE UPDATE/DELETE トリガーで不変)。管理者機能・passkey 署名は存在しない *(未実装)* |
| Message tampering post-receipt | User claims they received something different | 監査ログハッシュチェーンは実装済み。メッセージ単位の Merkle 葉/日次ルート公開は *(設計意図・未実装)* |

### 2.4 Information disclosure

| Threat | Example | Control |
|---|---|---|
| Tracking pixel | Sender sees when you opened | kaname-privacy がトラッキングピクセルを検出し、iframe CSP `img-src cid:` で外部読み込みを遮断 (実装済み)。KMPP リレー事前フェッチ/IP 秘匿/開封時刻ランダム化は *(設計意図・未実装)* |
| Metadata leak in headers | `X-Mailer`, internal hostnames, message-ID format | 送信メッセージは RFC 5322 で最小構成 (D94) — X-Mailer 等は付与しない。既存ヘッダの「除去/正規化」機能は *(未実装)* |
| Search index leakage | Cloud indexing reveals content | Index is local-only; no cloud search telemetry |
| HNDL (Harvest Now, Decrypt Later) | Attacker records TLS now, decrypts in 15 years | Hybrid PQC (ML-KEM-768 + X25519) from day 1 |
| Memory-scraping malware on device | Endpoint is already compromised | 鍵は 0600 ファイル/DB (SQLCipher) に保管、トークンは Zeroizing メモリのみ — SE 非対応のためユーザーモードマルウェアには残存リスク |
| Misdelivery | User sends to wrong recipient | 送信前 DLP プリチェック (mail_dlp_precheck: タイポドメイン誤配/機微情報) は実装済み。大量外部宛警告・送信取消ウィンドウは *(設計意図・未実装)* |
| Forensics by device seizure | Corporate IT or adversary acquires device | アプリレベル暗号化 (SQLCipher history.db/mls.db) は実装済み。MDM リモートワイプは *(設計意図・未実装)* |

### 2.5 Denial of service

| Threat | Example | Control |
|---|---|---|
| Attachment ZIP bomb | Recursive archive explodes on decompress | アプリは添付を展開しない (検査後にディスク保存のみ)。展開系の分離 VM は *(設計意図・未実装)* — 展開を実装するなら別経路で再検討要 |
| Regex DoS in filter rules | User Sieve script triggers worst-case regex | Sieve エンジン/ユーザールールは存在しない *(未実装 — 実装時は RE2 系エンジン必須)* |
| MIME parse bomb | Pathological MIME tree | Parser has depth cap (8) and field count cap (256); fuzz-tested |
| Mailbox flood | Attacker sends 1M messages | 受信側レート制限/クォータは JMAP サーバ側の責務。クライアント側の対策 (一覧の 500 件上限・オフライン cap) のみ実装 |
| Font/image parser exploit causing crash | Crafted ttf/png | フォント/画像は WebView (iframe sandbox + CSP) が描画。WASM/Firecracker VM 分離は *(設計意図・未実装)* — WebView プロセスのクラッシュは残存リスク |

### 2.6 Elevation of privilege

| Threat | Example | Control |
|---|---|---|
| HTML/CSS renderer escape | CVE in WebView | 本文は sandboxed `iframe` (no scripts/forms/popups 許可なし + CSP `default-src 'none'` + iframe `csp` 属性二重適用) で描画。アプリ側が別プロセス分離/seccomp を張る実装は**無い** — 隔離は sandbox 属性と CSP に依存する (WebView 自体の脆弱性は残存リスクとして別項で扱う) |
| Attachment viewer RCE | 0-day in PDF/Office viewer | アプリ内ビューアは存在しない — 添付はマジックバイト/SVG/polyglot/.ics 検査を通してディスクに保存し、OS の外部アプリで開く (kaname-render scan)。分離 VM ビューアは**未実装**であり「安全に開ける」保証はない |
| Sandbox escape to host | WebView/iframe サンドボックスの CVE | Accept as residual risk; patching cadence + defense in depth (iframe sandbox + CSP の多層防御) |
| Local privilege escalation to steal SE key | Malicious user-mode app | SE access requires biometric + app entitlement; OS provides the actual barrier |
| Admin-token theft | Session token stolen, admin actions taken | Admin actions require passkey re-auth (not cached); short-lived token; IP anomaly detection |

---

## 3. AI-specific threats

These do not fit STRIDE neatly. They are the reason Kaname exists.

### 3.1 Indirect prompt injection
**Threat**: Attacker embeds instructions in an email body. A naïve AI assistant processing the email interprets the instructions as legitimate.
**Example cases**: EchoLeak (2024, Microsoft 365 Copilot), Gemini agentic exfiltration (2025), Apple Intelligence hijack (RSAC 2026).
**Control**: Dual-LLM architecture (ADR-001). Privileged LLM never sees untrusted content; Quarantined LLM has no tools.
**Residual risk**: Social-engineering the human — attacker convinces user to manually copy-paste instructions into the trusted pane. Mitigation: training + UI hints that the trusted pane is where YOU type.

### 3.2 Direct prompt injection
**Threat**: User of our app types a jailbreak into the assistant.
**Scope**: Not our problem. User directing their own AI to do things within policy is fine.
**Control**: N/A — trusted by construction.

### 3.3 Fake conversation injection
**Threat**: Untrusted content contains `User:` / `Assistant:` markers to trick the model into reading a fake prior turn.
**Control**: Preflight scans for role-marker patterns. Quarantined LLM's system prompt explicitly declares that content between `<untrusted>` tags is not a conversation.
**Residual risk**: Novel chat-template tokens (for models we haven't seen) — monitor.

### 3.4 Multi-step agentic exfiltration
**Threat**: Multi-message sequence where AI's reasoning across steps causes data leakage (e.g., "summarize and cite the URL `<encode-data-here>`").
**Control**: All AI-emitted URLs are rewritten to go through Kaname relay (user-visible domain); any markdown image in AI output is blocked and rendered as `[image hidden]`. Cross-email AI operations require explicit user scope selection.
**Residual risk**: Undiscovered chain patterns. Mitigation: adversarial corpus §D is updated weekly.

### 3.5 AI recommendation poisoning
**Threat**: Attacker plants persistent instructions in the model's memory (where persistent memory exists) that later influence recommendations.
**Example**: Microsoft Security research, Feb 2026 — instructions embedded in web pages behind "Summarize with AI" plant memory.
**Control**: Kaname does not maintain cross-session LLM memory. Each query is stateless. If we ever add memory, the content will be in `Content<Trusted>` only (user-typed).
**Residual risk**: If a local LLM model itself is poisoned pre-deployment (supply chain), this would bypass us. Mitigation: model hash pinning and reproducible model builds.

### 3.6 Training data poisoning
**Threat**: Attacker influences training data of upstream models.
**Scope**: Out of our direct control (we don't train models).
**Control**: Models are versioned and pinned by hash; reported model misbehavior triggers rollback to previous known-good.

### 3.7 AI-generated phishing at scale
**Threat**: Attackers use LLMs to craft perfectly localized, contextually appropriate phishing, defeating static heuristics.
**Control**: Our BEC detector also uses an LLM — it assesses context, tone shift from past sender, and semantic anomalies (urgent + payment + unusual route). Asymmetric: our defender LLM is local and sees user's historical context; attacker's LLM is blind.
**Residual risk**: Very well-targeted spear phishing. Mitigation: BEC detector is one signal among many; verified-sender UI is the strongest signal for most attacks.

### 3.8 Deepfake audio/video attachments
**Threat**: Attachment is a deepfake impersonating the CEO.
**Control**: Out of scope for text defense, but we display prominent "sender verified" badge. If the attachment requests wire transfer action, the mail text itself will have BEC markers; alarm fires there.
**Residual risk**: A video attachment with no text context. Documented: users should verify high-value instructions out-of-band. We will add provenance metadata (C2PA) detection in v2.

### 3.9 Adversary-in-the-Middle (AiTM) phishing
**Threat**: Attacker stands up a reverse-proxy (Evilginx, Modlishka) between victim and legitimate SaaS login page. Captures live session cookie after real MFA completion; bypasses MFA entirely. Once session is hijacked, attacker injects payment-redirect emails or changes MX to intercept future mail.
**Control**: `kaname-bec` `AitmDetector` checks for:
- Redirect chains traversing known AiTM infrastructure (blocklist in `AITM_INFRASTRUCTURE`)
- Mismatched final landing domain vs. claimed SaaS platform domain (Levenshtein + homoglyph)
- Phishing kit fingerprints in URL path (`/security`, `/verify`, `/oauth2/v2.0/authorize` with suspicious query params)
- Urgency + credential request pattern in email body
**Detection point**: Inbound link analysis before user clicks; URL extracted from `<a href>` and evaluated in `kaname-render` pipeline.
**Residual risk**: Zero-day AiTM proxies not yet in blocklist; novel phishing kit paths. Mitigation: BEC LLM signal covers semantic urgency even without URL blocklist match; OOBV ceremony enforced for high-value wire transfers regardless.
**Implementation**: `crates/kaname-bec/src/aitm.rs`; assessment integrated into `BecDetector::assess()` via `check_aitm()` signal family.

### 3.10 QR 構造亜種による画像スキャン回避 (2026-07 追加)
**Threat**: 分割QR (Structured Append) で悪意ある URL を複数の QR に分割する、`blob:`/`data:`/`javascript:` スキームをペイロードに使う、等の構造的亜種により「QR をデコードして URL を照会する」型の防御を回避する。2026-03 には 28 通のキャンペーンが全てのセキュリティツールを素通りした事例が報告された (ReversingLabs/Acronis)。
**Control**: `kaname-render::quishing` — (a) 非 http(s) の危険スキーム (`blob:`/`data:`/`javascript:`) を `Suspicious` に格上げ、(b) `assess_multi_qr()` が同一メール内の QR 個数から分割 QR 兆候を判定 (`MultiQrRisk::SplitQrSuspected` = 3個以上)、(c) `detect_ascii_qr()` がブロック文字の高密度な連続行をテキスト解析のみで検出 (画像デコード不要)。2026-07 更新: (d) **動的 QR 対策** — 短縮 URL / QR リダイレクトサービス (bit.ly, qrco.de, flowcode.com 等) を `Suspicious` 判定。配信時は無害ページを指し検査通過後に差し替える手法のため、スキャン時点の宛先検証では防げず、検証不能な参照そのものを疑う (2026 上半期に quishing 約 146% 増、FBI が 2026-01 に Kimsuky/APT43 の利用を警告)。(e) **テキスト QR 文字集合の拡張** — 幾何学記号・絵文字ブロック・**点字ブロック U+2800..U+28FF** (2x4 ドット/文字でテキスト QR レンダラの主流) を追加 (Barracuda 観測)。
**Residual risk**: `detect_ascii_qr` は密度・行数ヒューリスティックであり、`#`/`@` 等の非ブロック文字だけで描かれた QR や、意図的に密度を下げた亜種は未検出。短縮 URL 判定は静的リストであり、自前ドメインのリダイレクタは検出不能 (リダイレクト追跡には実ネットワークアクセスが必要で、P-LLM 不可侵条件 I4 との整合を要検討)。実際の QR デコード (画像添付分) は `rqrr` 統合待ち。

### 3.11 CalPhishing — カレンダー自動登録の永続化悪用 (2026-07 追加)
**Threat**: `METHOD:REQUEST` の .ics は多くのクライアントで受信時に自動 tentative 登録され、**元メールをスパム判定・削除してもカレンダーエントリが残る**。攻撃者はこの永続化に緊急性偽装や不審 URL を組み合わせ、削除したはずの攻撃がカレンダーから再度ユーザーに提示される (SC Media "CalPhishing" 2026, KnowBe4)。
**Control**: `kaname-render::calendar_guard` — `CalendarRisk::AutoRegistrationAbuse`。METHOD:REQUEST/PUBLISH と他のフィッシング兆候の併存で検出し、警告文で「カレンダー側のエントリ削除が必要」であることを明示 (メール削除だけでは不十分という attacker asymmetry をユーザーに伝える)。
**Residual risk**: 正規招待も METHOD:REQUEST を使うため、他の兆候ゼロの標的型攻撃 (綺麗な招待文+後日差し替え) は検出できない。SEQUENCE 単調性チェック (§既存) が差し替え時の第二防衛線。

### 3.16 Dual-LLM 型境界の実効性 — 宣言と実装の分離 (2026-07 監査で追加)
**Threat**: Kaname の中核的な防御は「`Content<Untrusted>` は Q-LLM にのみ渡り、`Bridge` を通らない昇格は型エラー」という**コンパイル時の型強制**である。2026 年の研究 (CaMeL / FIDES / Progent、arxiv 2606.26479 の適応的評価) は、防御が「振る舞いではなくアーキテクチャによる保証」へ収束したと整理しており、Kaname の主張はさらに強い型レベルの保証にあたる。この保証が実際には成立していない場合、**製品の中核的な安全性の前提そのものが崩れる**。
**実態 (2026-07 監査 → 2026-09-20 更新)**: 型境界の**定義** (`dual_llm.rs`) は堅牢で、監査時の欠陥 (a) serde 偽造ルート、(b) `as_text()` の `pub` 公開、(d) `TopicTag` の Deserialize 迂回はすべて解消済み。(c) 出荷推論経路 `bec_score`/`bec_score_subprocess` は D147 で **`&Content<Untrusted>` 必須**に変更され、呼出側 (kaname-ui) が `Content::from_network` で provenance 付きに包まないとコンパイルできない構造になった。`impl QuarantinedLlm for` / `impl PrivilegedLlm for` 自体は依然 0 件だが、出荷経路は trait ではなく Content 必須の関数 API で型強制される。(4) `SubprocessMode::Privileged` の sandbox プロファイルに `(allow network-outbound)` があるが、**出荷経路で Privileged モードを spawn するコードは存在せず** (enum 値と設定のみ残存)。macOS では spawn 時に sandbox-exec seatbelt を適用、Linux/Windows は未実装のためフェイルクローズ (D128)。`resources/seccomp/` 参照は残存するが実行経路では未使用。
**Control (現状)**: I3 の中核のみ実効性がある — `Content` のフィールドは全て private、`Content<Trusted>` の公開コンストラクタは `from_user_input`/`from_system` の2つのみ、Bridge 専用昇格路 `from_validated` は `pub(crate)`、`#![deny(unsafe_code)]` により `transmute` 不可、`compile_fail` doc テストも実在する。Bridge の検証ロジック (email_id 一致・score 範囲・topics 数・攻撃マーカー・OutputAuditor) も実質的。
**Residual risk (2026-09-20)**: LLM 推論はスタブではなく出荷済み — 不信メール本文は `Content<Untrusted>` のまま `bec_score_subprocess` に入り、`kaname-llm-runner` サブプロセス (Q-LLM、macOS seatbelt 適用) で処理される。**出荷経路の I1 型境界は実効する** (入口が `&Content<Untrusted>` を要求し、内部でだけ `as_text()` で取り出す — 外部クレートは `Content` を包まなければ呼べない)。残リスク: (i) Privileged モードの `(allow network-outbound)` プロファイルと I4 の矛盾は未解決 — ただし同モードを spawn するコードがないため非活性 (P-LLM を配線する PR は I4 との整合を同時に決める必要がある)、(ii) 型境界は「kaname-ai の入口で Content を要求する」形の強制であり、クレート内の `&str` API を直接呼ぶ経路はクレート内規約に留まる。残作業は `docs/gap-analysis.md` D17 を参照。

### 3.15 DKIM リプレイ攻撃 / DMARC OR trap (2026-07 追加)
**Threat**: 攻撃者が正規組織 (Google/PayPal/Apple 等) から届いた DKIM 署名済みメールを入手し、そのまま別の宛先へ再送する。署名は有効なままなので DKIM は pass する。**DMARC は SPF と DKIM の OR 判定 (AND ではない) ため、SPF が転送で落ちても DKIM 側の alignment だけで DMARC も pass** してしまう。結果、受信側には「認証を完全に通過した正規メール」に見える。2025 年に Google をスプーフィングする実被害が発生。
**Control**: `kaname-bec::check_dkim` — DKIM 署名ドメイン (`d=`) と表示上の From ドメインの整合を検証する。正規メールでは `d=` は From ドメイン (またはその親ドメイン) と揃うため、不一致は第三者署名かリプレイの強い指標になる。DKIM が pass しているケースほど「認証通過に見える」ため重み付けを高くする (0.40 / 未pass時 0.20)。既存の `DkimReplayTracker` (同一署名の複数回観測) と併せて多層で検出する。
**Residual risk**: 正当な第三者送信サービス (メール配信基盤等) は `d=` が異なることがあり、単独では誤検知になり得るため、他シグナルとの複合で評価する設計としている。また転送メーリングリストは SPF fail + DKIM pass の形を取るが、`d=` が整合していれば本シグナルは発火しない。

### 3.15b 送信ドメイン認証を独立検証していない (2026-07 監査で判明・要記録)
**Threat**: Kaname の認証シグナル (`SignalFamily::Authentication`、§3.15 の DKIM リプレイ検出を含む) は、すべて `AssessmentRequest.auth` に渡される SPF/DKIM/DMARC/ARC の**判定結果**を前提にしている。その供給元は `kaname-render::parse_auth_results` であり、実装は受信サーバが付与した `Authentication-Results` ヘッダを**文字列としてパースするだけ**である。ワークスペース全体に DKIM 署名の暗号検証コードは存在しない (RSA/Ed25519 の署名検証呼び出しがゼロ件)。したがって**認証系の全判定は「受信サーバが書いた内容を信じる」ことに帰着する**。
**現状の位置づけ**: メールクライアントが自組織の信頼された MTA が付けた `Authentication-Results` を信頼すること自体は RFC 8601 が想定する正常な設計であり、これ単独を脆弱性とは呼べない。**問題はこの信頼前提が脅威モデルに一度も明記されていなかったこと**、および以下2点の実装上の弱さである。
- **authserv-id を検証していない**: RFC 8601 §7.1 は、ヘッダ消費者が先頭の authserv-id が**自分の信頼する認証サーバのものか**を確認することを要求している。Kaname は `find()` で最初の `Authentication-Results` を無条件に採用し、authserv-id を一切見ていない (リポジトリ全体で `authserv` の言及がゼロ)。信頼境界外の中継が付与したヘッダを信じ得る設計になっている。
- **パースが素朴な部分文字列探索**: `extract_auth_result` は `lower.find("dkim=")` のように最初の一致を採る。`smtp.mailfrom=` / `header.d=` / `header.from=` 等の**攻撃者が影響し得る echo フィールドやコメント**が機構名より前に現れると、誤った値を拾う余地がある (現行の完全一致 `"pass"` 判定により実際の成立条件は狭いが、構造的に脆い)。
**Control (今後)**: 独立検証は [`mail-auth`](https://github.com/stalwartlabs/mail-auth) (Stalwart Labs) で実現できる。**Kaname が既に採用している `mail-parser` と同一ベンダ**であり (ADR-009)、DKIM (RSA/Ed25519)・ARC 連鎖検証・SPF/DMARC ポリシー評価を備える。さらに 2026-07 時点で **DKIM2 と DMARCbis (RFC 9989/9990/9991, 2026-05) を実装済み**。
**DKIM2 が §3.15 に与える影響 (重要)**: DKIM2 はメッセージを**宛先にバインドし送信時刻を記録**することで、リプレイ攻撃をプロトコルレベルで解決する。また転送時に署名が壊れない chain of custody を導入するため、§3.15 で扱った「SPF fail + DKIM pass + DMARC pass」という曖昧な状態自体が解消される。**したがって §3.15 で実装した `d=` と From の整合ヒューリスティックは DKIM1 時代の暫定策であり、DKIM2 対応が入れば本来不要になる**。DMARCbis は静的な Public Suffix List を DNS tree walk に置き換える。
**Residual risk (2026-09 に「悪用不能」から「悪用可能」へ格上げ)**: D10 (メールパイプライン未配線) は解消され、`parse_auth_results` には実メール (ローカル `.eml` 取込みと、JMAP サーバから受信した blob の両方) が流れている。**独立検証は依然として実装されておらず、この文書が当初「配線時のリスク」として記述していた状態が現在の稼働状態そのものになった**: `Authentication-Results` ヘッダを転送する中継 (接続先 JMAP サーバ、あるいはそのサーバへ至る経路上の中継) が SPF/DKIM/DMARC すべて `pass` を主張するヘッダを付与すれば、Kaname の BEC 判定はそれを暗号的検証なしに信頼する。authserv-id の検証も無いため、信頼境界外の中継が付けたヘッダも無条件に採用される。攻撃条件は「ユーザーが接続する JMAP サーバ (または経路上の中継) を攻撃者が制御・偽装できること」であり、任意の第三者が任意のメールに対して行える攻撃ではない点で影響範囲は限定的だが、**もはや理論上の懸念ではない**。残作業 (`mail-auth` による独立検証・authserv-id 検証の実装) は `docs/gap-analysis.md` D18 を参照。

### 3.14 SVG 添付によるスクリプト実行・フィッシング (2026-07 追加)
**Threat**: SVG は「画像」でありながら XML であり、`<script>`・イベントハンドラ・`<foreignObject>` を含められる。ブラウザで開くと JavaScript が実行されるため、無害な画像に見せかけてフィッシングページをローカル展開したりトークンを窃取できる。悪意ある SVG 添付は 2024 年比で **50 倍**に増加 (2025 年)、2026 年 2 月の単一キャンペーンで **120 万通が 53,000 組織**へ配信された。観測された回避手法: (a) `type="application/ecmascript"` という非推奨 MIME 型でのスクリプト宣言 (ブラウザは `text/javascript` と同一に扱うが多くのスキャナが未検査)、(b) EML→SVG→base64 iframe の多層エンコード、(c) `<script>` を使わないイベントハンドラ実行。
**Control**: `kaname-render::svg_guard` — `scan_svg()` が `<script>` (type 属性も監査証跡として記録)・イベントハンドラ・`javascript:`/`vbscript:` スキーム・`<foreignObject>`・base64/`atob()` を検出し、実行リスクがあれば `safe_as_attachment = false`。また `magic_bytes::is_svg` が先頭 256 バイトしか走査せず長いコメントで `<svg` を押し下げると回避できたため、8 KB まで走査する `looks_like_svg()` を追加。**2026-07 追補**: `magic_bytes::detect_mime_from_magic` 本体の SVG 走査窓も 256 バイト → 8 KB に拡張した。従来は押し下げ SVG が MIME 検出をすり抜けるため、`check_mime_mismatch` が「SVG を `image/png` と偽装した添付」を見逃していた。併せてデコードを `from_utf8` → `from_utf8_lossy` に変更 (前者は走査窓の末尾でマルチバイト文字が切れると**文字列全体が空になり判定が丸ごと失われる**という欠陥があり、窓を広げるほど発現確率が上がるため)。
**Threat (追加, 2026-07)**: **マルチモーダル・プロンプト注入 (Polyglot SVG Attack)** — SVG は画像でありながら XML のため、`<desc>`・**XML コメント (描画されない)**・**CDATA セクション**に「命令」を潜ませられる。人間の目には正規の画像でも、それを処理する AI は指示として読む。研究では画像埋め込み命令がテキスト層のサニタイズを迂回し、ステルス条件下で最大 64% の攻撃成功率を示す (arxiv 2603.03637 / CSA research note 2026-03)。XML/SVG では CDATA 悪用と XXE 形式ペイロードが名指しされている。
**Control (追加)**: `scan_svg()` が `<title>`/`<desc>`/`<text>`/`<tspan>`/XML コメント/CDATA から「AI が読み得るテキスト」を抽出し `kaname-screen::PromptScreener` にかける (`SvgRisk::PromptInjectionAttempt`)。判定方針は `calendar_guard` と同一 — 原文のまま渡し、`Blocked` のみ採用、`HighEntropy` は除外して正規文の誤検出を防ぐ。加えて `<!DOCTYPE`/`<!ENTITY` を `SvgRisk::XmlExternalEntity` として検出 (XXE / billion laughs の入口)。
**Residual risk**: 文字列走査ベースであり完全な XML パーサーではないため、極端な難読化 (XML 実体参照による `<script>` の分割等) は検出漏れし得る。注入検出は `PromptScreener` の確定的マーカーに依存するため、既知パターンに一致しない自然言語の誘導は捕捉できない。**画素に描かれた typographic 注入 (画像レンダリング後にのみ現れる文字) は本モジュールの対象外** — テキスト走査では原理的に検出できず、OCR/画像解析が必要。SVG 添付は本来メールで受け取る必然性が乏しいため、UI 側で既定拒否とする運用が望ましい。**2026-09 訂正**: 「`svg_guard` が添付処理パイプラインに未配線」という記述は誤りだった。`kaname-render::scan_attachments` (`lib.rs:1022-1023`) が SVG 判定時に `svg_guard::scan_svg` を実際に呼んでおり、D10 解消後は実メール添付に適用されている。

### 3.12 カレンダー招待経由のプロンプト注入 (2026-07 追加)
**Threat**: .ics の DESCRIPTION/SUMMARY に命令上書きフレーズ・LLM特殊トークン・不可視 Unicode タグ等を埋め込む。現状の Kaname では .ics 本文が AI 要約に渡る経路は無いが、(a) UI にそのまま表示され得る、(b) 将来カレンダー統合が Dual-LLM 要約対象になった場合に `kaname-screen` を経由しない入力経路が成立する、という2点で入口検査に値する (§3.1 間接注入のカレンダー版)。
**Control**: `kaname-render::calendar_guard` — DESCRIPTION/SUMMARY を `kaname-screen::PromptScreener::screen()` にかけ、`Blocked` 判定 (確定的マーカー一致) を `CalendarRisk::PromptInjectionAttempt` として Danger 報告。エントロピー単独の `Suspicious` は文字種の多い正規日本語文の誤検出を招くため不採用。
**Residual risk**: `Suspicious` を捨てるトレードオフにより、未知パターンの難読化注入 (高エントロピーのみが兆候) は検出しない。Dual-LLM 側の出力監査 (`kaname-ai` の Bridge/AuditResult) が第二防衛線。

### 3.13 SaaSリンク経由のプロンプト注入 (2026-07 追加)
**Threat**: 正当な SaaS ドメイン (Google Drive/DocuSign 等) や偽装ドメインへのリンクのクエリパラメータ (`?note=`, `?comment=` 等) に命令上書きフレーズや LLM 特殊トークンを仕込み、SaaS連携を装いつつプロンプト注入を狙う複合攻撃。従来の `SaasLinkInspector::evaluate()` はドメイン一致・キーワード一致のみでクエリの文面内容を検査していなかった。
**Control**: `kaname-saas-guard::SaasLinkInspector::evaluate()` — URL全体を `kaname-screen::PromptScreener::screen()` にかけ、`Blocked` 判定で `SaasLinkRisk::Block` に格上げ。偽SaaSドメイン検出 (§既存の `is_fake_saas_subdomain`) との併存も確認済み (Suspicious→Block)。
**Residual risk**: §3.12 と同じトレードオフ (`Suspicious`/`HighEntropy` 単独は不採用)。

---

## 4. Supply chain

| Threat | Control |
|---|---|
| Compromised Cargo dependency | `cargo-vet` (with allow-list); crates from stdlib/rustcrypto/tokio orgs preferred; audit new deps in PR review |
| Compromised Tauri plugin | We ship zero third-party plugins (ADR-006) |
| Compromised Firecracker kernel/rootfs image | We build images reproducibly from source; hash pinned in release manifest |
| Compromised LLM model file | Model hash pinned; alternate model fallback; downloaded over HTTPS from our CDN with Ed25519 + ML-DSA manifest signature |
| Compromised update channel | Updates are signed with hardware-rooted key (SE/TPM-gated); clients verify both Ed25519 and ML-DSA signatures on manifest |
| Compromised developer workstation | Signing is gated by hardware token presence + two-person approval for release branches |

---

## 5. Cryptographic agility

We assume current algorithms will eventually weaken:

- All crypto operations carry an algorithm identifier
- The algorithm set is configured, not hardcoded
- We can add HQC (FIPS 2027) as backup KEM without code changes
- If ML-DSA is found weak, we can switch to SLH-DSA (hash-based, conservative) via configuration
- If X25519 is ever broken, the hybrid falls back to pure PQC; users notified
- Migration paths for existing encrypted archives (re-wrap keys) documented in `docs/crypto-migration.md`

---

## 6. Insider threat (partial coverage)

We do not claim to fully defend against determined insider attack with admin privileges:
- An admin with console access can grant themselves mailbox access
- The compensating control is the **hash-chained audit log**: such an access is recorded, cannot be modified retroactively, and triggers notifications to other admins (quorum-style)
- Data exfiltration to external channels is detected by DLP (pattern scan on outbound)
- Admin actions require passkey re-auth → no stolen-session compromise

A rogue insider with biometric access to their own machine can read their own mail. This is accepted.

---

## 7. Risk register (top 10)

Ranked by `likelihood × impact`:

1. **Novel indirect prompt injection technique** — likelihood high, impact medium (limited by architecture)
2. **Kernel 0-day bypassing Firecracker isolation** — likelihood low, impact high
3. **Targeted spear phishing exploiting trust UX** — likelihood high, impact medium
4. **Mis-configured customer deployment exposing admin console** — likelihood medium, impact high
5. **Cryptographic library CVE in ring/openmls** — likelihood low, impact high
6. **Supply chain compromise of a Cargo dep** — likelihood low, impact high
7. **User loses device / key files (`history.key`/`mls.key`), no recovery path** — likelihood medium, impact medium (data loss, not disclosure)。現状鍵は 0600 ファイルであり SE ではない (復旧経路の設計は未着手)
8. **LLM model file compromised in distribution** — likelihood low, impact medium
9. **Apple/Microsoft OS CVE affecting webview** — likelihood medium, impact medium
10. **Legal subpoena / CLOUD Act against Kaname servers** — likelihood medium, impact high **for content** is low (server holds encrypted blobs only for Kaname-to-Kaname), medium for metadata (we minimize but don't eliminate)

---

## 8. Controls coverage matrix

| Control | Addresses threats |
|---|---|
| Dual-LLM architecture (ADR-001) | 3.1, 3.3, 3.4 |
| Firecracker microVM for attachments (ADR-005) | 2.6, 3.8, F-class payloads |
| WASM/seccomp HTML sandbox | 2.6, C-class payloads |
| Hybrid PQC (ADR-004) | 2.4 HNDL, §5 |
| MLS E2E (ADR-003) | 2.1, 2.2, 2.4 |
| Passkey + Secure Enclave | 2.1, 2.4, §6 admin |
| KMPP relay | 2.4 tracking, metadata |
| Hash-chained audit log | 2.3, §6 insider |
| BIMI/DMARC/ARC verification | 2.1 spoofing |
| Local-only AI (ADR-001) | 2.4 content exfil, 3.1 |
| Reproducible builds + SBOM | §4 supply chain |
| Adversarial test corpus | 3.1-3.5 regression |

---

## 9. Changelog

- **v1.0 (2026-04-18)**: Initial threat model aligned with ADRs 001-006.
- **v1.1 (2026-06-14)**: §3.9 AiTM 追加; BEC スコアリングをロジスティック変換に移行; `Content::from_attachment()` の UserUpload provenance 修正; Bridge の PhaaS マーカー拡充 (10件追加); topics フィールドのマーカースキャン追加.
- **v1.2 (2026-07-10)**: §3.10 QR 構造亜種 (分割QR/危険スキーム/ASCIIアートQR)、§3.11 CalPhishing 自動登録永続化、§3.12 カレンダー招待経由のプロンプト注入、§3.13 SaaSリンク経由のプロンプト注入 (kaname-screen 統合) を追加。2026-07 の研究調査 (docs/research-2026-07.md) に基づく.
- **v1.5 (2026-09-20)**: JMAP セッション応答 URL (`apiUrl`/`downloadUrl`/`uploadUrl`) のオリジン検証を追加 — サーバ応答に外部ホストを含めると Bearer トークンが外部へ流出する経路を閉塞 (§2 STRIDE-Information Disclosure、D83)。併せて downloadUrl/uploadUrl テンプレート変数の URL エンコード (D82) で添付名由来のパス改変を防止。
- **v1.3 (2026-07-13)**: Ultracode 徹底監査 (3エージェント並列、全27クレート) で発見したセキュリティ修正を反映: (a) kaname-store の SQLCipher 生鍵を `Zeroizing` でゼロ化 (§5 暗号アジリティ / コアダンプ経由の鍵漏洩対策)、(b) kaname-jmap のリダイレクトに `safe_redirect_policy` を適用し DNS リバインディング型 SSRF を閉塞 (§2 STRIDE-Spoofing/EoP)、(c) kaname-oobv の OOBV 推奨キーワード照合を全角/ゼロ幅正規化経由に変更しバイパスを防止 (§3.9 AiTM の電話確認回避対策)、(d) kaname-observability の PII サニタイザが数字始まりメールアドレスを見逃していた検出漏れを修正 (I5 ログ PII 混入防止)。あわせて BEC 検出器への kaname-pivot/kaname-screen 統合、kaname-radar のキャンペーン集計バグ、kaname-mls 開始者側のリプレイ検出漏れを修正。詳細は docs/gap-analysis.md フェーズ4・5。

- **v1.4 (2026-09-20)**: D75 — 「SQLCipher で暗号化」の対策記述が実効していなかったことを反映。rusqlite は `bundled` (素の SQLite3) でビルドされており `PRAGMA key` が no-op、DB は平文だった。`bundled-sqlcipher` への切替で `cipher_version=4.5.3` 動作を実測確認し、回帰テストを固定。「対策」の主張が成立していたのはこの時点から。あわせて鍵の実保管場所を正記述 (0600 ファイル; SE/Keychain は未実装のまま)。

Future versions will be deltas; we don't rewrite from scratch.

## 検証境界

暗号実装の検証境界 (何が機械検証済みで何が信頼ベースか) は [verification-boundary.md](verification-boundary.md) に明示。arxiv eprint 2026/192「Verification Theatre」の教訓を反映している。
