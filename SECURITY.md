# セキュリティポリシー

Kaname は法人のセキュアコミュニケーションを支えるソフトウェアです。脆弱性報告には全力で対応します。

## サポート対象バージョン

| バージョン | サポート状況 |
|---|---|
| 0.7.x (最新) | ✅ セキュリティパッチ優先適用 |
| 0.6.x | ✅ 重大な脆弱性のみ対応 |
| < 0.6.0 | ✗ サポートなし (アップグレード推奨) |

**2026-09 訂正**: このドキュメントは長らく v0.3.x を最新と記載したまま
更新されていなかった (最終更新日は変えず、本セクションのみ実態に合わせた)。

## 報告経路

**公開 GitHub Issue では報告しないでください。**

1. **GitHub Security Advisory** (推奨): リポジトリの Security タブ → Report a vulnerability
2. **暗号化メール**: security@kaname.app 宛、PGP 公開鍵で暗号化
3. **Signal**: 鍵検証用 Safety Number は kaname.app/contact に掲載

## 対応 SLA

| 期限 | 対応内容 |
|---|---|
| 24時間以内 | 受領確認 |
| 72時間以内 | CVSS v3.1 重大度評価 |
| 7日以内 | 修正計画と公開予定日を共有 |
| 30日以内 | 修正リリース (重大度に応じて短縮) |
| 公開後30日 | CVE 採番と詳細公開 |

## 重大度分類

### 🔴 Critical (CVSS 9.0+)
- RCE / 認証バイパス / 暗号鍵漏洩
- MLS プロトコル違反による平文露出
- **Dual-LLM 境界違反** (Untrusted データが PrivilegedLlm に到達)

### 🟠 High (CVSS 7.0-8.9)
- ローカル権限昇格
- DLP バイパス (Microsoft Copilot CW1226324 相当)
- 監査ログ改ざん

### 🟡 Medium (CVSS 4.0-6.9)
- 個人情報以外の情報漏洩 / DoS / レート制限バイパス

### 🟢 Low (CVSS < 4.0)
- ヘッダー欠落 / バナー露出

## 対象外
- ソーシャルエンジニアリング
- 物理アクセス前提の攻撃
- 3rd party 既知脆弱性 (cargo audit で追跡)
- 悪用不可能なベストプラクティス違反

## 主要保護メカニズム

**2026-09 訂正**: 以下の一覧は設計意図を実装済みと誤って記載していた。
`docs/gap-analysis.md`/`docs/threat-model.md` に基づく実際の状態に修正する
(脆弱性報告者がこのドキュメントを根拠に誤った前提で判断しないため)。

1. **Dual-LLM 型安全**: **設計上の意図であり、現時点では実装が伴っていない**
   (`docs/gap-analysis.md` D17)。`Content<Untrusted>`/`Bridge` の型定義自体は
   堅牢だが、実推論経路 `llm_bridge.rs` はこれらの型を経由しない生 `&str` API
   であり、`impl QuarantinedLlm for` / `impl PrivilegedLlm for` はワークスペース
   全体で0件。現状は LLM 推論自体がスタブのため悪用可能な経路は無いが、
   LLM 実装を配線する際にこの境界を同時に塞がない限り、その瞬間に悪用可能になる
2. **MLS RFC 9420**: **未実装** (`docs/gap-analysis.md` D1)。現状は単一バイト
   XOR のモックで、暗号として機能していない。件名を含む暗号化は行われていない
3. **DLP ラベル強制**: 実装済み・実データで稼働 (`kaname-dlp`)
4. **Firecracker microVM**: **未実装** (`docs/gap-analysis.md` D4)。
   `spawn_vm`/`VsockChannel` は no-op で、添付は実行されずサンドボックス隔離
   もされない。添付検査 (`kaname-render` の各種検出器) はサンドボックスとは
   独立して実データで動作する
5. **改ざん防止監査ログ**: `kaname-observability` に実装済み。運用への
   組み込み状況は `docs/gap-analysis.md` を参照

## 報奨

現金報奨金はないが、重要な脆弱性報告者には:
- セキュリティ Hall of Fame 記載 (希望者)
- CHANGELOG への謝辞
- 製品ライフタイムライセンス進呈

## 自動セキュリティチェック

```bash
cargo audit --deny warnings    # 脆弱性
cargo deny check all           # ライセンス + 禁止クレート
npm audit --audit-level=moderate
```

許可された例外は `deny.toml` に理由と再評価期限を記録。

## 第三者監査計画

| 評価 | 実施年 | 公開 |
|---|---|---|
| 暗号設計レビュー | Q3 2026 | 公開予定 |
| ペネトレーションテスト | Q3 2026 | 要約のみ |
| ソースコード監査 | Q4 2026 | 要約のみ |

---

**最終更新**: 2026-04-26 / **ポリシー版**: 1.0
