#!/usr/bin/env bash
# scripts/stats.sh — Kaname プロジェクト統計

set -uo pipefail

cd "$(dirname "$0")/.."

JSON_MODE=false
[[ "${1:-}" == "--json" ]] && JSON_MODE=true

RUST_FILES=$(find crates src-tauri -name "*.rs" 2>/dev/null | wc -l)
RUST_LOC=$(find crates src-tauri -name "*.rs" 2>/dev/null | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
TS_FILES=$(find src e2e -name "*.ts" -o -name "*.tsx" 2>/dev/null | wc -l)
TS_LOC=$(find src e2e -name "*.ts" -o -name "*.tsx" 2>/dev/null | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
CRATE_COUNT=$(ls crates/ 2>/dev/null | wc -l)
UNIT_TESTS=$(grep -rh '^    #\[test\]\|^    #\[tokio::test\]' crates/ 2>/dev/null | wc -l)
E2E_TESTS=$(grep -rh '^test(' e2e/ 2>/dev/null | wc -l)
VITEST_TESTS=$(grep -rh 'it(' src/__tests__/ 2>/dev/null | grep -c "it(" 2>/dev/null || echo 0)
PROP_TESTS=$(grep -rh 'proptest!' crates/ 2>/dev/null | wc -l)
FUZZ_TARGETS=$(ls fuzz/fuzz_targets/*.rs 2>/dev/null | wc -l)
TODOS=$(grep -rh 'todo!\|unimplemented!' crates/ src-tauri/ 2>/dev/null | grep -v '^\s*//' | grep -c '.' 2>/dev/null || echo 0)
UNWRAPS=$(grep -rh '\.unwrap()' crates/ 2>/dev/null | wc -l)
PANICS=$(grep -rh 'panic!' crates/ src-tauri/ 2>/dev/null | wc -l)
DOC_CRATES=$(grep -l "^//!" crates/*/src/lib.rs 2>/dev/null | wc -l)
README_CRATES=$(ls crates/*/README.md 2>/dev/null | wc -l)
DOCS_FILES=$(find docs/ -name "*.md" 2>/dev/null | wc -l)

if [[ "$JSON_MODE" == true ]]; then
cat << JSON
{
  "rust": { "files": $RUST_FILES, "loc": $RUST_LOC, "crates": $CRATE_COUNT },
  "typescript": { "files": $TS_FILES, "loc": $TS_LOC },
  "tests": {
    "unit_rust": $UNIT_TESTS, "vitest": $VITEST_TESTS,
    "playwright": $E2E_TESTS, "proptest": $PROP_TESTS, "fuzz": $FUZZ_TARGETS
  },
  "quality": {
    "todos": $TODOS, "unwraps": $UNWRAPS, "panics": $PANICS,
    "documented_crates": $DOC_CRATES, "crates_with_readme": $README_CRATES
  },
  "documentation": { "doc_files": $DOCS_FILES }
}
JSON
  exit 0
fi

cat << REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Kaname プロジェクト統計
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Rust (workspace)
   ├─ クレート:        $CRATE_COUNT
   ├─ ファイル数:       $RUST_FILES
   └─ 行数 (LOC):       $RUST_LOC

📜 TypeScript / TSX
   ├─ ファイル数:       $TS_FILES
   └─ 行数 (LOC):       $TS_LOC

🧪 テスト
   ├─ Rust ユニット:    $UNIT_TESTS
   ├─ vitest:          $VITEST_TESTS
   ├─ Playwright E2E:  $E2E_TESTS
   ├─ プロパティ:       $PROP_TESTS
   └─ ファジング標的:    $FUZZ_TARGETS

✅ コード品質
   ├─ todo!():          $TODOS
   ├─ unwrap():         $UNWRAPS
   ├─ panic!():         $PANICS
   └─ ${DOC_CRATES}/${CRATE_COUNT} クレートに //! ドキュメント

📚 ドキュメント
   ├─ ${README_CRATES}/${CRATE_COUNT} クレートに README.md
   └─ docs/ 内: $DOCS_FILES ファイル

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT
