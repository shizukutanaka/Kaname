# Kaname 改善拡大 Wave 1 — EXPANSION-REPORT

日付: 2026-11-28
ブランチ: `exp/kaname`
ベースライン commit: `fa99c25` (`fix(render): #883 ...`)

## 1. ベースライン実測

pristine な worktree (変更なし) で確認した。

### Rust

コマンド:

```bash
cargo test --workspace --offline
```

結果: **46 test suites / 3,415 passed / 0 failed / 1 ignored**

補足: 初回はこの実行環境側の不足依存 (`gdk-3.0` development files、続いて `libclang`) でビルドできなかった。GTK/WebKitGTK/libclang の development package を入れた後の上記が pristine ベースラインである。`cargo-nextest` は環境に無かったため、repository で利用可能な `cargo test --workspace --offline` を使った。

### Frontend unit

コマンド:

```bash
npm run test:unit
```

結果: **1 test file passed / 6 tests passed / 0 failed**

## 2. 反復で得た視点

チェックリストに沿って見た項目:

- **同名添付の上書き (データ消失)**: D87 として既に `write_unique` が `create_new` + `name (1).ext` 化を実装し、既存テスト `write_unique_は同名を別名で保存し既存を上書きしない` も緑だった。新たな最優先欠陥ではない。
- **mockserver の permissive CORS / Host 検証なし**: 実在するが、用途は開発/E2E fixture で default bind は loopback。実メール内容を保持する製品経路ではないため、今回の一件には選ばなかった。
- **記録と実態のずれ**: `docs/gap-analysis.md` の crates.io 未到達という記述は、現在の環境では populated registry により offline build が進んだため実態とずれている。ただし利用者のデータへ直接危害する欠陥ではない。
- **添付の隔離保存権限 (守りの欠落)**: `mail_download_attachment` が `/tmp/kaname-attachments` に保存し、directory/file とも mode 指定がなかった。添付内容は `docs/threat-model.md` で最上位資産 “Message body and attachment content” と明示されている。

権限は実コードと同じ `create_dir_all` + `OpenOptions::create_new(true)` を使う Rust 再現で実測した:

```text
umask 022:
/tmp/kaname-perm-repro-dir 755
/tmp/kaname-perm-repro-dir/report.pdf 644
umask 027:
/tmp/kaname-perm-repro-dir 750
/tmp/kaname-perm-repro-dir/report.pdf 640
```

ソクラテス問答:

- **なぜ問題と言えるか**: Linux/macOS の `/tmp` は共有名前空間であり、umask 022 では他ローカルユーザーが添付内容を読める。umask 027 でも group readable であり、添付の機密性を保証しない。
- **反証は何か**: デスクトップ利用の多くは単一ユーザーであり、同一ユーザー権限の malware にはファイル権限は効かない。したがって全脅威を止めるものではない。しかし threat model は insider/endpoint 上の一部権限を部分的に考慮しており、他ローカルユーザーへの world/group readable 保存は明確に不要な露出。
- **やめたら何が起きるか**: 受信添付が予測可能な共有ディレクトリに、利用者の意図より広い権限で残る。添付スキャンで危険判定を通過した合法文書ほど、そのまま読まれる。
- **要件を削れるか**: 保存場所の再設計や Firecracker 隔離は今回の一件の範囲外。最小要件は「既存の隔離保存先を所有者専用にし、ファイルは作成瞬間から owner-only にする」こと。新規実行時依存は不要。

## 3. 選んだ最優先項目

**添付隔離ディレクトリと添付ファイルの permission 欠落**を修正した。

選定根拠: 実コード、実測 permission、threat model の資産順位の3点で裏付けられ、チェックリスト (a)「秘密・複製ファイルの権限」に直接該当する。D87 の上書き修正は存在したが、confidentiality の穴は残っていた。

## 4. 変更内容

変更ファイル: `crates/kaname-ui/src/commands.rs` のみ。新規依存なし。

1. `attachment_quarantine_dir_in` を追加。
   - Unix では `DirBuilderExt::mode(0o700)` で隔離ディレクトリを最初から 0700 として作成。
   - 既存ディレクトリが 0755 等なら 0700 に矯正。
   - 隔離パスが symlink の場合は chmod せず fail-closed で拒否。
2. `mail_download_attachment` はこの helper 経由で隔離ディレクトリを準備する。
3. `write_unique` は Unix で `OpenOptionsExt::mode(0o600)` を指定し、添付ファイルを作成瞬間から 0600 にする。write 後 chmod の窓は作らない。
4. 不変条件テストを2件追加。
   - `write_uniqueは添付を0600で作成する`
   - `attachment_quarantine_dir_inは0700に矯正しsymlinkを拒否する`

既存の D87 テストは削除・弱化していない。

## 5. 変更後の検証

### Rust

コマンド:

```bash
cargo test --workspace --offline
```

結果: **46 test suites / 3,417 passed / 0 failed / 1 ignored**

追加した2件を含む。`write_uniqueは添付を0600で作成する` と `attachment_quarantine_dir_inは0700に矯正しsymlinkを拒否する` は両方 pass。

### Frontend unit

コマンド:

```bash
npm run test:unit
```

結果: **1 test file passed / 6 tests passed / 0 failed**

### Format / static checks

```bash
cargo fmt --all --check
./scripts/static-check.sh
```

結果: 両方 pass。`static-check.sh` は「静的検証: 問題なし」。既存の警告として、複数 detector に属する header prefix 30件の注記は出るが失敗ではない。

## 6. 既知の残存リスク・未検証項目

- 変更後の最初の full test run では、今回の変更と無関係な `kaname-ai::subprocess::tests::healthcheck_はモックプロセスで成功する` が `Broken pipe (os error 32)` で一度だけ失敗した (その run は kaname-ai が 68 passed / 1 failed で停止)。再実行した full workspace run は 3,417/3,417 緑だった。コードを読む限り、`spawn_mock` が即終了する `true` を child に使い、healthcheck の stdin write と child exit が競合する既存 flake。今回は「最優先1件だけ」の制約を守るため修正しなかったが、次回候補として価値が高い。
- 実 JMAP server/account を使った end-to-end の添付 download は未検証。検証したのは保存先準備とファイル作成の unit invariant。
- Unix permission だけを固定した。Windows/macOS 実機上の動作は未検証 (macOS も Unix 系だが実行環境は Linux)。
- 既に旧バージョンが 0644 で保存した既存ファイル個々の mode は変更しない。ただし親ディレクトリが 0700 になるため、通常の他ユーザー traversal は閉じる。
- `cargo clippy` は今回実行していない。`cargo test` による型検査、`cargo fmt --check`、repository の `static-check.sh` は実施した。
