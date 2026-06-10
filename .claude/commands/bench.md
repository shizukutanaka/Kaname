# /bench [target]

ベンチマークを実行して Apple HIG 目標と比較する。

## コマンド
```bash
cargo bench --bench core_bench [-- target_name]
```

## 目標値
`.claude/skills/performance.md` を参照

## 回帰判定
5% 以上の遅化があれば `performance-regression` を報告。
