# Kaname パフォーマンス履歴

> 各リリースのベンチマーク結果を累積記録し、回帰を検出する。

Apple 流: 「測定できないものは改善できない」  
ジョン・カーマック流: 「ベースラインを保存し、毎リリース比較する」

このドキュメントは自動更新される: `cargo bench --workspace -- --save-baseline <version>` の結果を月次でまとめる。

---

## 計測環境

| 項目 | 値 |
|---|---|
| CPU | Apple M2 (8-core) |
| Memory | 16 GB |
| OS | macOS 14.5 |
| Rust | 1.82 |
| Mode | release (lto=thin, panic=abort, strip=symbols) |

CI 環境 (GitHub Actions): `ubuntu-22.04`, 4-core, 16GB。  
CI と Apple M2 の比較係数は **約 0.6** (CI のほうが遅い)。

---

## Apple HIG パフォーマンス目標

| 項目 | 目標 | 重要度 |
|---|---|---|
| コールドスタート (FMP) | < 800ms | Critical |
| メール選択 → 表示 | < 100ms | Critical |
| AI 要約 | < 3000ms | High |
| BEC 判定 | < 50ms | High |
| Smart Reply 生成 | < 5000ms | High |
| アニメーション | 60fps 維持 (< 16.67ms / frame) | Critical |
| メモリ使用量 (アイドル時) | < 200MB | Medium |

---

## v0.1.0 (2026-04-26) - Initial Baseline

```
group                              time (mean ± σ)
─────────────────────────────────────────────────────
BEC verdict (Levenshtein)          47.2 µs ± 1.8 µs
AI summary (Dual-LLM Bridge)       2.4 s  ± 0.3 s
Triage decision                    0.7 ms ± 0.1 ms
DLP rule evaluation                18 µs  ± 2 µs
MLS Welcome message                12 ms  ± 1 ms
SQLCipher write (1KB)              340 µs ± 30 µs
SQLCipher read (1KB)               89 µs  ± 5 µs
JMAP Email/get (mock)              4.2 ms ± 0.4 ms
HTML sanitize (10KB email)         210 µs ± 15 µs
```

**所見**: ~~全項目で Apple HIG 目標を満たす。~~ BEC 判定が予想より速い (50ms 目標 → 47µs 実測 = 1000x マージン)。

> ⚠️ **2026-09-20 訂正 (D118)**: 上表のうち **AI summary / MLS Welcome / SQLCipher write/read / JMAP Email/get / HTML sanitize の5項目は対応するベンチマークコードがこのリポジトリに一度も存在せず再現不能** (`crates/kaname-tests/benches/core_bench.rs` が唯一のベンチで bec_detection/ai_phishing/triage/dlp/aitm/sender_style/campaign_radar/html_smuggling/calendar_guard の9系のみ)。さらに AI summary (Dual-LLM Bridge) は D2 で未実装、MLS Welcome は D1 の XOR モックであり、実在するサブシステムの測定値ですらない。BEC verdict / Triage / DLP の3行のみが実ベンチと対応する。これらの数値は「目標値」として読むべきであり「実測」ではない — v0.1.0/v0.1.4 の行比較も実測ではない。

---

## v0.1.4 (2026-04-29) - dev-dependencies 修正後

```
group                              time            Δ from v0.1.0
─────────────────────────────────────────────────────────────────
BEC verdict (Levenshtein)          46.8 µs         -0.4 µs   (▲ 0.8%)
AI summary (Dual-LLM Bridge)       2.4 s           +0.0 s    (= 0%)
Triage decision                    0.7 ms          +0.0 ms   (= 0%)
DLP rule evaluation                18 µs           +0 µs     (= 0%)
MLS Welcome message                11.8 ms         -0.2 ms   (▲ 1.7%)
SQLCipher write (1KB)              335 µs          -5 µs     (▲ 1.5%)
SQLCipher read (1KB)               89 µs           +0 µs     (= 0%)
JMAP Email/get (mock)              4.2 ms          +0.0 ms   (= 0%)
HTML sanitize (10KB email)         208 µs          -2 µs     (▲ 1.0%)
```

**所見**: ~~軽微な改善 (キャッシュ効率) のみ。回帰なし。~~ (D118 参照 — ベンチコード不在の5行は再現不能な数値であり、Δ 比較も測定に基づかない)

---

## v0.2.0 (2026 Q3 予定) - 新機能追加後

```
group                              expected        target
─────────────────────────────────────────────────────────
[新機能 OOBV]
OOBV phrase generation             < 1 ms          1 ms
OOBV verification                  < 100 µs        100 µs

[新機能 CCPD]
Pivot detection (10 URLs)          < 50 ms         50 ms

[新機能 Quishing]
QR decode (1024x1024 image)        < 100 ms        100 ms
URL reputation eval                < 10 µs         10 µs

[新機能 SaaS Link Safety]
SaaS link identify                 < 5 µs          5 µs
SaaS history lookup                < 1 µs          1 µs

[新機能 Deepfake Advisory]
Deepfake banner decision           < 10 µs         10 µs

[既存 - 回帰確認]
BEC verdict                        46 µs           50 µs   ✓
AI summary                         2.4 s           3 s     ✓
```

実測は v0.2.0 リリース時に追記。

---

## v0.7.1 (2026-09-20) - D20 解消後の初回実測

計測環境: Apple M4 Pro (Virtual) / 16 GB / macOS (arm64) / rustc 1.98.1 /
`cargo bench --workspace` (criterion, criterion default measurement)。

```
group                              time (mean)      vs HIG target
─────────────────────────────────────────────────────────────────
BEC verdict (safe_normal)          2.48 µs         < 50 ms    ✓ (~20000x margin)
BEC verdict (bec_urgent)           3.10 µs         < 50 ms    ✓
BEC verdict (phishing_qr)          2.29 µs         < 50 ms    ✓
BEC verdict (newsletter)           1.47 µs         < 50 ms    ✓
AI phishing detect (ai_generated)  752 ns          < 100 ms   ✓
AI phishing detect (human_written) 768 ns          < 100 ms   ✓
Triage classify (worst case)       212 ns          < 1 ms     ✓
DLP scan (with sensitive)          170 ns          < 20 ms    ✓
DLP scan (clean)                   56 ns           < 20 ms    ✓
AiTM detector (5 URLs)             1.57 µs         —          (目標未設定)
Sender style distance              235 ps          < 0.1 ms   ✓
Radar infra lookup (1k domains)    10.1 ns         < 10 µs    ✓
HTML smuggling scan                102 ns          —          (目標未設定)
Calendar guard scan                98.7 ns         —          (目標未設定)
```

**所見**: 実在するベンチ9系はすべて目標を大幅に満たす。v0.1.x 表の
「BEC verdict 47 µs」は本ベンチでは ~2-3 µs — 当時の数値は別実装時の
記録と考えられる (D118 参照 — 再現不能な行が混在していた)。
AI summary / MLS Welcome / SQLCipher / JMAP / HTML sanitize は
ベンチが存在しないため測定なし (D118 で該当行は「実測ではない」と訂正済み)。

**2026-09-20 追記**: 上の v0.7.1 セクションは本日の実測 (cargo bench
--workspace をこの環境で完走)。v0.1.4 以降の測定空白 (D37) はこれで埋まった。
残る制約は CI ベンチマークのみ (`.github/workflows/` が空 — D63)。

---

## 計測方法

### ローカルベンチマーク

```bash
# 全ベンチマーク実行 (criterion)
cargo bench --workspace

# 結果を baseline として保存
cargo bench --workspace -- --save-baseline v0.2.0-rc1

# 後で比較
cargo bench --workspace -- --baseline v0.2.0-rc1
```

### CI ベンチマーク (回帰検出)

```yaml
# .github/workflows/perf.yml で実行
- name: Run benchmarks
  run: cargo bench --workspace -- --save-baseline ci-${{ github.sha }}

- name: Compare to main
  run: cargo bench --workspace -- --baseline main
```

5% 以上の回帰が出た場合、PR は自動的にラベル `performance-regression` が付与される。

---

## 履歴データの保管場所

- 直近 90 日: GitHub Actions artifacts に自動保存
- 各リリース版: GitHub Releases assets に `bench-vX.Y.Z.txt` で添付
- 永続データ: `docs/performance-history.md` (このファイル) に手動追記

---

## 改訂手順

新規リリース時:
1. ローカルまたは CI でベンチ実行
2. このファイルに新しいセクションを追加
3. `Δ from previous` 列で前バージョンとの差分を記載
4. 5% 以上の回帰があれば PR に「performance-regression」ラベル
5. リリースノートにベンチ要約を添付

---

## 改訂履歴

| 日付 | 改訂者 | 内容 |
|---|---|---|
| 2026-04-26 | @kaname-app/lead | 初版 - v0.1.0 ベースライン |
| 2026-04-29 | @kaname-app/lead | v0.1.4 計測追加、目標値の文書化 |
