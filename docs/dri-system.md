# Kaname DRI (Directly Responsible Individual) System

> Apple 内部運用の核心。あらゆる決定に「one name attached」。

最終更新: 2026-04-29 | DRI: kaname-organization

---

## 1. DRI とは何か

Apple では、すべてのプロジェクト・課題・機能・バグに **ただ 1 人の責任者** が割り当てられる。チームではなく、特定の個人。

> 「Whose phone do I call at 2am?」

その答えが DRI の役割を一言で表す。

DRI は:
- 最終的な意思決定権を持つ
- 状況をエスカレーションする責任を持つ
- 問題が解決するまでフォローする
- その領域の知識を最も深く持つ

---

## 2. Kaname での DRI 構造

### 2.1 モジュール DRI

各 Rust クレートに 1 名の DRI を割り当てる。

| クレート | DRI 役割 | スキル要件 |
|---|---|---|
| `kaname-ai` | AI Safety Lead | Rust 型システム、Phantom Type、LLM、プロンプト注入 |
| `kaname-mls` | Cryptography Lead | MLS RFC 9420、HPKE、E2E 暗号 |
| `kaname-crypto` | Cryptography Lead | ML-KEM-768、ハイブリッド暗号、PQC |
| `kaname-bec` | Threat Intelligence Lead | 詐欺検出、フィッシング、Levenshtein |
| `kaname-dlp` | Compliance Lead | DLP、データ分類、SOC2 |
| `kaname-render` | Sandbox Lead | mXSS、HTML サニタイザ、ファジング |
| `kaname-sandbox` | Sandbox Lead | Firecracker、microVM、seccomp |
| `kaname-jmap` | Mail Protocol Lead | JMAP、IMAP、SMTP 仕様 |
| `kaname-store` | Storage Lead | SQLCipher、AES-256、SQL 設計 |
| `kaname-ui` | Frontend Lead | Tauri、SolidJS、TypeScript |
| `kaname-tray` | macOS Integration Lead | Cocoa、AppKit、メニューバー |
| `kaname-i18n` | Localization Lead | CLDR、BCP 47、多言語 |
| `kaname-billing` | Business Operations Lead | Stripe、エンタイトルメント |
| `kaname-continuity` | Apple Platform Lead | Handoff、iCloud、UserActivity |
| `kaname-observability` | SRE Lead | Prometheus、tracing、SLI/SLO |
| `kaname-privacy` | Privacy Lead | GDPR、トラッキング検出 |
| `kaname-mockserver` | DevX Lead | E2E テスト、開発者体験 |
| `kaname-error` | Foundation Lead | 共通基盤、API 設計 |
| `kaname-core` | Architecture Lead | 全体設計、依存グラフ |

### 2.2 機能 DRI

各製品機能に DRI を割り当てる。

| 機能 | DRI 役割 |
|---|---|
| Dual-LLM 型安全 | AI Safety Lead |
| BEC 多信号検出 | Threat Intelligence Lead |
| Smart Reply 3 候補 | AI Safety Lead |
| Quick Look 添付 | Sandbox Lead |
| Cmd+Z Undo/Redo | Frontend Lead |
| ⌘K コマンドパレット | Frontend Lead |
| 自然言語検索 | Frontend Lead + Localization Lead |
| Liquid Glass UI | Design Lead |
| Handoff 連続性 | Apple Platform Lead |
| Stripe ライセンス | Business Operations Lead |
| MLS Safety Number | Cryptography Lead |
| トラッキング保護 | Privacy Lead |
| 起動時間 < 800ms | SRE Lead |

### 2.3 業務領域 DRI

| 領域 | DRI 役割 |
|---|---|
| インシデント対応 | Security Lead |
| リリース判断 | Engineering Lead |
| App Store 申請 | Business Operations Lead |
| Design Partner 関係 | Customer Success Lead |
| プレスリリース | Communications Lead |
| 法務対応 | Legal Lead |

---

## 3. DRI の権限と責任

### 3.1 DRI が持つ権限

- ✓ そのモジュール/機能の **設計判断の最終決定権**
- ✓ PR のマージ承認権 (該当領域の)
- ✓ 緊急時の優先順位変更権
- ✓ 競合する判断の解決権
- ✓ ベンダー選定権 (該当領域の)

### 3.2 DRI が持つ責任

- ✗ 該当領域のバグ・障害の最終責任
- ✗ ロードマップの実行責任
- ✗ ドキュメントの最新性
- ✗ 関連 Issue の triage 速度 (24h 以内)
- ✗ 該当領域の知識継承 (退職時)

### 3.3 DRI に求められる行動

| 行動 | 期限 |
|---|---|
| 該当領域の Issue triage | 報告から 24h 以内 |
| バグ重要度判定 | triage と同時 |
| Critical バグ修正 | 7 日以内 |
| High バグ修正 | 30 日以内 |
| Medium バグ修正 | 90 日以内 |
| ドキュメント更新 | 機能リリース時 |
| 月次レビュー参加 | 必須 |

---

## 4. エスカレーション経路

```
Module DRI (例: AI Safety Lead)
    ↓ (24h で判断不可)
Engineering Lead
    ↓ (3 日で判断不可)
CEO / Founder
    ↓ (重大インシデント)
Board of Advisors (招集)
```

DRI は **判断を保留せず**、自分で解決できないと判断したら **24 時間以内** に上位にエスカレーション。

---

## 5. DRI ハンドオフ手順

DRI が変わる時の手順:

1. **後任が決定** → 既存 DRI が変更を docs/dri-table.md に PR
2. **30 日のオーバーラップ** → 既存 DRI と新 DRI が並行運用
3. **知識継承文書** → docs/runbook/{crate}.md に運用知識を書き出し
4. **PR 承認権の移譲** → CODEOWNERS ファイルを更新
5. **公式アナウンス** → CHANGELOG.md に記載

---

## 6. CODEOWNERS との同期

`.github/CODEOWNERS` で各クレートの DRI を GitHub レベルで強制する:

```
# Module DRIs
/crates/kaname-ai/        @ai-safety-lead
/crates/kaname-mls/       @cryptography-lead
/crates/kaname-crypto/    @cryptography-lead
/crates/kaname-bec/       @threat-intelligence-lead
...
```

PR は該当 DRI の承認が必須。これにより **DRI 不在の決定は構造的に不可能** になる。

---

## 7. 月次 DRI レビュー (Apple Friday Reviews)

### 形式

- 毎月最終金曜日、2 時間
- 全 DRI 出席必須
- アジェンダ: 各 DRI が領域の状態を 5 分で報告

### 報告項目

各 DRI は以下を報告:

1. **過去 30 日の主な変更**
2. **未解決の重要 Issue 数**
3. **ロードマップ進捗 (% 完了)**
4. **依存関係のリスク**
5. **支援が必要な事項**

### 出力

- 全 DRI レビュー議事録 → `docs/reviews/{YYYY-MM}.md`
- 行動項目 → GitHub Issue として登録
- ブロッカー特定 → 翌週までに解消計画

---

## 8. DRI 無き決定のアンチパターン

❌ **やってはいけないこと:**

- 「チームで決めました」 → DRI 不在、責任の所在が曖昧
- 「Slack で多数決しました」 → 専門知識を無視した決定
- 「全員で議論したい」 → 時間浪費、決断力欠如
- 「本部長が決めます」 → DRI の権限を弱体化
- 「投票しました」 → 集団責任化

✓ **やるべきこと:**

- 「[名前] が DRI として、X を Y にすると判断しました」
- 「DRI が休暇中なので、副 DRI に判断を委譲します」
- 「DRI が決定し、その理由を ADR に記録しました」

---

## 9. 適用状況の自動チェック

CI で `scripts/check-dri.sh` を実行し、以下を検証:

```bash
# 1. すべてのクレートに DRI が割り当てられている
# 2. CODEOWNERS と docs/dri-table.md が同期している  
# 3. PR が DRI の承認を受けている (GitHub Branch Protection)
```

違反があれば PR ブロック + Slack に警告。

---

## 10. 参考文献

- "Inside Apple" by Adam Lashinsky (Chapter 4: DRI)
- "The Cult of the Mac" by Leander Kahney
- Apple Internal Engineering Handbook (非公開)
- "Get Things Done" by David Allen (DRI に類似する概念)

---

## 11. 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-29 | kaname-organization | 初版 — Apple DRI 実装 |
