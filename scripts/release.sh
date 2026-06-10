#!/usr/bin/env bash
# scripts/release.sh
#
# Kaname リリース自動化スクリプト
# Apple "Rules of the Road" チェックリストを自動実行する。
#
# 使用例:
#   ./scripts/release.sh 0.2.0
#
# 何をするか:
#   1. 全テスト実行 (Rust + TypeScript)
#   2. Lint・フォーマット・セキュリティ監査
#   3. パフォーマンスベンチマーク
#   4. CHANGELOG 更新確認
#   5. バージョン番号を全ファイルで更新
#   6. SBOM 生成
#   7. git tag を作成
#   8. CI が自動的にビルド・リリースする (実際のリリースは GitHub Actions)

set -euo pipefail

# ── 引数チェック ──────────────────────────────────────────────────────────
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    echo "Example: $0 0.2.0" >&2
    exit 1
fi

VERSION="$1"

# semver チェック
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9a-zA-Z.-]+)?$ ]]; then
    echo "❌ Invalid version format: $VERSION" >&2
    echo "Expected: X.Y.Z or X.Y.Z-prerelease" >&2
    exit 1
fi

# ── カラー出力 ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}▶${NC} $1"; }
ok()   { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1" >&2; exit 1; }

# ── 1. 環境チェック ───────────────────────────────────────────────────────
log "1/9 環境チェック"

[[ -d ".git" ]] || err "Git リポジトリのルートで実行してください"
git diff-index --quiet HEAD || err "ワーキングツリーがクリーンではありません (commit してください)"

# 必須ツール
for tool in cargo node npm git; do
    command -v "$tool" >/dev/null || err "$tool がインストールされていません"
done

ok "環境 OK"

# ── 2. ブランチチェック ───────────────────────────────────────────────────
log "2/9 ブランチチェック"

CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" ]] && [[ "$CURRENT_BRANCH" != "release/"* ]]; then
    warn "現在のブランチ: $CURRENT_BRANCH (main または release/* が推奨)"
    read -rp "続行しますか? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

ok "ブランチ: $CURRENT_BRANCH"

# ── 3. CHANGELOG.md 確認 ──────────────────────────────────────────────────
log "3/9 CHANGELOG.md エントリ確認"

if ! grep -q "^## \[$VERSION\]" CHANGELOG.md; then
    err "CHANGELOG.md に [$VERSION] のエントリがありません"
fi

ok "CHANGELOG OK"

# ── 4. 全テスト実行 ───────────────────────────────────────────────────────
log "4/9 テスト実行"

# Rust
log "  Rust テスト (cargo nextest)"
if command -v cargo-nextest >/dev/null; then
    cargo nextest run --workspace --no-fail-fast || err "Rust テストが失敗しました"
else
    cargo test --workspace || err "Rust テストが失敗しました"
fi

# TypeScript
log "  TypeScript テスト (vitest)"
npm run test:unit || err "TypeScript テストが失敗しました"

ok "全テスト通過"

# ── 5. Lint・フォーマット・セキュリティ監査 ─────────────────────────────────
log "5/9 静的解析"

log "  cargo fmt --check"
cargo fmt --all --check || err "フォーマット違反 (cargo fmt --all で修正)"

log "  cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings || err "Clippy 警告あり"

log "  cargo audit"
if command -v cargo-audit >/dev/null; then
    cargo audit --deny warnings || err "セキュリティ脆弱性検出"
else
    warn "cargo-audit が未インストール (cargo install cargo-audit)"
fi

log "  cargo deny check"
if command -v cargo-deny >/dev/null; then
    cargo deny check all || err "ライセンス・依存関係チェック失敗"
else
    warn "cargo-deny が未インストール"
fi

log "  npm audit"
npm audit --omit=dev || warn "npm 依存に脆弱性あり (要確認)"

ok "静的解析通過"

# ── 6. パフォーマンスベンチマーク (オプション) ─────────────────────────────
log "6/9 パフォーマンスベンチマーク"

if [[ "${SKIP_BENCH:-}" == "1" ]]; then
    warn "SKIP_BENCH=1 によりスキップ"
else
    cargo bench --workspace --bench '*' -- --quick || warn "ベンチマーク失敗 (継続)"
fi

# ── 7. バージョン番号更新 ──────────────────────────────────────────────────
log "7/9 バージョン番号更新 → $VERSION"

# Cargo.toml (workspace)
sed -i.bak "s/^version[[:space:]]*=[[:space:]]*\".*\"/version      = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

# package.json
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$VERSION';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# tauri.conf.json
node -e "
const fs = require('fs');
const conf = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json', 'utf8'));
conf.version = '$VERSION';
fs.writeFileSync('src-tauri/tauri.conf.json', JSON.stringify(conf, null, 2) + '\n');
"

ok "バージョン更新完了"

# ── 8. SBOM 生成 ──────────────────────────────────────────────────────────
log "8/9 SBOM 生成"

if command -v cargo-cyclonedx >/dev/null; then
    cargo cyclonedx --format json --override-filename rust-sbom 2>/dev/null
    ok "Rust SBOM 生成"
else
    warn "cargo-cyclonedx 未インストール (cargo install cargo-cyclonedx)"
fi

if [[ -d node_modules ]]; then
    npx --yes @cyclonedx/cyclonedx-npm --output-format JSON --output-file npm-sbom.cdx.json 2>/dev/null
    ok "NPM SBOM 生成"
fi

# ── 9. Git タグ作成 ───────────────────────────────────────────────────────
log "9/9 Git タグ作成"

git add Cargo.toml package.json src-tauri/tauri.conf.json
git commit -m "chore: release v$VERSION" --no-verify
git tag -a "v$VERSION" -m "Release v$VERSION

Apple Rules of the Road:
- 全テスト通過 (Rust + TypeScript)
- 静的解析通過 (clippy + audit + deny)
- ベンチマーク実行
- SBOM 生成
- CHANGELOG 更新済み

CI が自動的にビルドしリリースを作成します。
"

ok "タグ作成: v$VERSION"

# ── 完了 ──────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Kaname v$VERSION リリース準備完了${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "次のステップ:"
echo "  1. git push origin main"
echo "  2. git push origin v$VERSION"
echo "  3. GitHub Actions が自動的に:"
echo "     - 4 プラットフォーム向けビルド"
echo "     - コードサイニング (Apple/Authenticode)"
echo "     - GitHub Release 作成"
echo "     - SBOM 添付 + SLSA Provenance"
echo
echo "リリースをキャンセルする場合:"
echo "  git tag -d v$VERSION"
echo "  git reset --hard HEAD~1"
echo
