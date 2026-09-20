# docs/competitive-analysis.md
# Kaname 競合分析 — 長所・短所・実装した改善

作成: 2026-04-25 | 情報源: 2026年市場調査

> **2026-09 訂正**: 「2. Kaname に実装した改善」「3. Kaname の独自優位性」の
> 表に、実際にはモック/スタブ段階、または出荷バイナリに配線されていない
> 項目が「実装済み」として含まれていた (`docs/brand-guidelines.md` D39・
> `SECURITY.md` D34 と同種)。該当項目に実態を注記した。

---

## 1. 競合マップと長所・短所

### カテゴリ A: 暗号化メールプロバイダー

| 製品 | 長所 | 短所 |
|---|---|---|
| **Proton Mail** | スイス管轄、OpenPGP 互換、Proton Bridge でデスクトップ対応、生態系 (VPN/Drive) | PGP = 前方秘匿なし、PQC なし、**件名が平文**、検索がサーバー側 |
| **Tuta (Tutanota)** | **件名暗号化**、ゼロ知識検索、TutaCrypt (Kyber-1024)、GDPR 準拠、低価格 | プロプライエタリ暗号で相互運用性低、UI が古い、ストレージ小 |
| **Mailfence** | 生産性ツール統合、鍵管理 UI、ベルギー管轄 | UX が散漫、大企業向け機能不足 |

### カテゴリ B: エンタープライズゲートウェイ

| 製品 | 長所 | 短所 |
|---|---|---|
| **Mimecast** | 暗号化 + DLP + ウイルススキャン一本化、受信後失効・転送制限 | 管理 UI が複雑、URL 書き換えが過剰・調整不可、高コスト |
| **Proofpoint + Tessian** | NexusAI 行動分析、受信後保護、VAP ダッシュボード | コンソール分断、高価格、Abnormal に 1,300 社流出 |
| **Abnormal Security** | API ネイティブ、行動 AI、侵害アカウント検出 | **クラウド専用** (M365/Workspace 依存)、**E2E 暗号化なし** |

### カテゴリ C: 2026 年の攻撃トレンド

QR コードフィッシングはフラグメントベース攻撃に進化している。BEC はもはや単一のなりすましではなく、複数のペルソナが協調する長期キャンペーンになっている。FBI IC3 は BEC で 2024 年に 27.7 億ドルの被害を記録した。

ベンダーメール詐欺 (VEC) は 2024 年に前年比 100% 増加した。テキストのみの BEC メールは署名マッチするコードも URL も添付もなく、従来型ゲートウェイを通過する。

---

## 2. Kaname に実装した改善

### 今回実装 (kaname-bec-advanced.rs + kaname-privacy-lib.rs)

| 改善 | 競合との差別化 | 実装クラス |
|---|---|---|
| **QR コードフィッシング検出** | Abnormal/Proofpoint も対応遅れ | `QrPhishingDetector` |
| **ベンダーメール詐欺 (VEC) 検出** | 振込先変更+ドメインスプーフィング+金額異常を統合 | `VendorEmailCompromisingDetector` |
| **配送後 URL 再スキャン** | Mimecast と同等機能をローカルで実装 | `PostDeliveryScanner` |
| **多ペルソナ BEC キャンペーン検出** | 業界初レベル (単一メール内でなく時系列で検出) | `MultiPersonaDetector` |
| **メール爆撃防御** | MFA 疲労と組み合わせた攻撃を検出 | `EmailBombingDefense` |
| **件名 MLS 暗号化** | ⚠️ **未実装** (`docs/gap-analysis.md` D1)。MLS は単一バイト XOR のモックで、暗号化は行われていない | `SubjectEncryption` |
| **トラッキングピクセル検出・ブロック** | Proton Mail と同等、Gmail より優位 | `TrackingDetector` |
| **ゼロ知識ローカル検索** | ❌ **削除済み (2026-09, E8)**。`ZeroKnowledgeSearch` は `kaname-privacy` に存在したが `kaname-ui` から一度も呼ばれておらず、実際に使われている検索 (`mail_search` → `kaname_store::search_messages`) は平文に対する LIKE 検索。未配線の代替実装は維持コストのみを生むため削除 — 将来必要になれば git 履歴から復元 | なし (削除済み) |

---

## 3. Kaname の独自優位性 (競合が真似できない)

| 優位点 | 理由 |
|---|---|
| **Dual-LLM 型安全** | ⚠️ **型定義のみで実装が伴っていない** (`docs/gap-analysis.md` D17)。trait 実装0件、実推論経路は型を経由しない生 `&str` API |
| **MLS RFC 9420 + PQC** | ⚠️ **未実装** (D1)。単一バイト XOR のモック |
| **ローカル AI 推論** | ⚠️ **未実装** (`docs/gap-analysis.md` D2)。`llm_bridge` は固定文字列を返すのみで実推論は行われていない |
| **Firecracker 添付分離** | ⚠️ **未実装** (`docs/gap-analysis.md` D4)。`spawn_vm`/`VsockChannel` は no-op |
| **VEC + QR + 多ペルソナ統合** | ✅ 実装済み・出荷バイナリに配線済み (`kaname-bec`/`kaname-render`) |
| **ゼロ知識検索** | ⚠️ **未配線** (上表参照)。実際の検索は平文 LIKE 検索 |

---

## 4. 残り改善候補 (次スプリント)

- AI エージェントへのプロンプト注入メール検出 (2026 年新脅威)
- サプライヤーリスクスコア継続更新
- 文体異常検出 (Tessian の核心機能)
- DMARC/BIMI 対応 (送信者ブランド認証の可視化)
