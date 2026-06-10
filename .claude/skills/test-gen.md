# skill: test-gen

テストコードを生成する。Kaname のパターンに準拠。

## 発火条件
- 「テスト書いて」「test を追加」「テストを生成」

## Kaname テストパターン

### 1. 正常系 + 攻撃系を必ずペアで書く
```rust
#[test]
fn legitimate_link_is_safe() { ... }

#[test]
fn phishing_link_is_detected() { ... }
```

### 2. AiTM/BEC/フィッシングの攻撃ケース
よく使う攻撃パターン:
- `microsoft.com.evil.tk` (ブランド偽装)
- `?id_token=eyJ` (AiTM トークン窃取)
- `至急振込` (BEC 緊急語)
- `Ignore previous instructions` (プロンプト注入)

### 3. プロパティテスト (proptest)
```rust
proptest! {
    #[test]
    fn score_always_in_range(input in ".*") {
        let score = compute_score(&input);
        prop_assert!((0.0..=1.0).contains(&score));
    }
}
```

### 4. 命名規約
```
test_[対象]_[条件]_[期待結果]
例: test_aitm_detector_token_in_url_returns_caution
```

## Gotchas
- `unwrap()` は test 内でのみ許可
- 攻撃パターンは実際の CVE や事例に基づくこと
- プロパティテストで不変条件を検証すること
