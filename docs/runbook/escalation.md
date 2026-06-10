# Runbook: エスカレーション

## 連絡先

| レベル | 連絡先 | 期待応答時間 |
|---|---|---|
| L1 (操作支援) | support@kaname.app | 24時間以内 |
| L2 (技術障害) | engineering@kaname.app | 4時間以内 (営業時間) |
| L3 (重大障害) | oncall@kaname.app | 1時間以内 (24/7) |
| L4 (セキュリティ) | security@kaname.app + PGP | 1時間以内 (24/7) |

## L3 エスカレーション基準

以下のいずれかで L3 に通報:
- 全ユーザーが影響を受ける障害
- データ損失の可能性
- セキュリティ侵害の疑い
- 復旧時間が 1 時間を超える見込み

## 情報収集 (L3 通報前に)

```bash
# ログ収集
mkdir incident-$(date +%Y%m%d-%H%M)
cd incident-*

# システム情報
uname -a > system.txt
defaults read /Library/Preferences/.GlobalPreferences AppleLocale 2>/dev/null >> system.txt

# Kaname ログ
cp ~/Library/Logs/Kaname/*.log . 2>/dev/null

# 統計
cat > stats.json <<JSON
$(curl -s http://localhost:9100/metrics 2>/dev/null || echo "{}")
JSON

tar czf incident.tar.gz *
```

このアーカイブを通報メールに添付してください。
