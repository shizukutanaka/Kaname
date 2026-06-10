# ADR-002: Q-LLM のサブプロセス分離

- **状態**: Accepted
- **日付**: 2026-04-16
- **影響範囲**: kaname-ai/subprocess.rs

## 文脈

ADR-001 で Dual-LLM を採用したが、Q-LLM (Quarantined LLM) が同一プロセス内で動作すると以下の攻撃面が残る:

1. **メモリ越境アクセス**: バッファオーバーフロー / Use-After-Free で他のメモリを読める
2. **共有グローバル状態**: tokio runtime, グローバル static, lazy_static の汚染
3. **ファイルディスクリプタ漏洩**: Q-LLM が誤ってネットワークソケットや DB ハンドルを取得
4. **シグナルマスク**: SIGCHLD 等の継承による親プロセスの操作

## 決定

Q-LLM は別プロセスで実行し、stdin/stdout のテキストパイプのみで通信する:

```rust
pub struct QuarantinedLlmImpl {
    process: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl QuarantinedLlmImpl {
    pub fn spawn() -> Result<Self> {
        let child = Command::new("kaname-q-llm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .env_clear()  // 環境変数を全て削除
            .spawn()?;
        // seccomp でネットワーク syscall をブロック (Linux)
        // sandbox-exec でファイル読み取りをブロック (macOS)
        // AppContainer でリソースを隔離 (Windows)
        Ok(...)
    }
}
```

### サンドボックス層 (OS 別)

| OS | 機構 | ブロックする syscall |
|---|---|---|
| Linux | seccomp-bpf | socket, connect, openat (読み取り以外), execve |
| macOS | sandbox-exec | network*, file-write*, mach-priv-task-port |
| Windows | AppContainer | INTERNET_CLIENT, INTERNET_CLIENT_SERVER |

## 結果

### 利点
- Q-LLM のメモリ破壊が親プロセスに波及しない
- ネットワーク操作が syscall レベルで阻止される (seccomp が SIGSYS で殺す)
- グローバル状態の汚染が不可能 (プロセス分離)

### コスト
- IPC オーバーヘッド: stdin/stdout で +5-10ms
- メモリ: Q-LLM プロセスが ~2GB 常駐
- 配布の複雑化: Q-LLM バイナリを別途同梱

## 検証

```rust
#[test]
fn q_llm_cannot_open_network_socket() {
    let q = QuarantinedLlmImpl::spawn().unwrap();
    // Q-LLM プロセス内で socket(AF_INET, ...) を試みると
    // seccomp が SIGSYS で殺すことを確認
    assert!(q.test_blocked_syscall("socket"));
}
```

---

# ADR-003: MLS RFC 9420 採用 (PGP/S-MIME を廃止)

- **状態**: Accepted
- **日付**: 2026-04-18
- **影響範囲**: kaname-mls, 暗号化メール全般

## 文脈

メール暗号化の業界標準は以下の2つだが、いずれも 1990年代の設計で深刻な制限がある:

### PGP の問題
- **件名が平文**: メタデータ漏洩 (誰が誰に何の件名で送ったか)
- **前方秘匿性なし**: 鍵漏洩で過去全メールが復号される
- **手動鍵管理**: ユーザーが公開鍵を交換する必要 (UX 破滅)
- **EFAIL 攻撃**: HTML メールでの平文露出

### S/MIME の問題
- 認証局 (CA) 依存: 中央集権的、CA 侵害で全鍵漏洩
- 件名平文 (PGP と同様)
- 鍵失効が事実上不可能

### MLS RFC 9420 の特性
- **件名を含む全暗号化**: メタデータ最小化
- **前方秘匿性 + 後方秘匿性**: 各メッセージで鍵を更新
- **自動鍵管理**: TreeKEM プロトコル
- **量子コンピューター対策**: ML-KEM-768 ハイブリッド KEM

## 決定

Kaname のすべての E2E 暗号化通信に MLS RFC 9420 を使う。PGP/S-MIME は提供しない。

```
平文メール → MLS Application Message → ML-KEM-768 + X25519 → 件名含む全暗号化
```

### ハイブリッド KEM
- 古典: X25519 (Curve25519)
- ポスト量子: ML-KEM-768 (FIPS 203, 2024)
- 共有秘密: HKDF-SHA-256 で結合

これにより**古典 ECDLP が破られても**かつ**量子コンピューターが ML-KEM を破られても**機密性が維持される (両方が破られない限り安全)。

## 結果

### 利点
- 件名平文の問題が完全に解決
- ハーベスト・ナウ・デクリプト・レイター攻撃に耐える
- TreeKEM で 100人グループでも O(log n) 鍵更新
- Signal Protocol を超える保護 (Signal は 2人/小グループのみ)

### コスト
- PGP との互換性なし (PGP ユーザーには平文 + 警告で送信)
- 受信者も Kaname または MLS 対応クライアントが必要
- TLS 経由では事前鍵登録 (KeyPackage) が必要

## 関連
- ADR-001: Dual-LLM 型安全
- ADR-006: Safety Number 検証 UX
- ADR-009: KeyPackage 配布プロトコル

## 参考
- RFC 9420 (2023): The Messaging Layer Security (MLS) Protocol
- FIPS 203 (2024): Module-Lattice-Based Key-Encapsulation Mechanism Standard
- PromptArmor (2026): なぜ PGP はもう使えないか
