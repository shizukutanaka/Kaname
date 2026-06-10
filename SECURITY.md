# セキュリティポリシー

Kaname は法人のセキュアコミュニケーションを支えるソフトウェアです。脆弱性報告には全力で対応します。

## サポート対象バージョン

| バージョン | サポート状況 |
|---|---|
| 0.3.x (最新) | ✅ セキュリティパッチ優先適用 |
| 0.2.x | ✅ 重大な脆弱性のみ対応 |
| 0.1.x | ⚠️ サポート終了 (アップグレード推奨) |
| < 0.1.0 | ✗ サポートなし |

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

1. **Dual-LLM 型安全**: `Content<Untrusted>` を `PrivilegedLlm` に渡すことはコンパイル時に不可能
2. **MLS RFC 9420**: 件名を含む全暗号化、ML-KEM-768 ハイブリッド KEM
3. **DLP ラベル強制**: HighlyConfidential/LegalPrivilege メールの AI 処理を完全ブロック
4. **Firecracker microVM**: 添付サンドボックス
5. **改ざん防止監査ログ**: 全 AI アクセスを FNV-1a ハッシュチェーンで記録

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
