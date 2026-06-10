# Makefile — Kaname 開発コマンド統一
#
# 使い方:
#   make          デフォルト: fmt + lint + test
#   make dev      開発サーバー起動
#   make test     全テスト
#   make bench    ベンチマーク
#   make release  リリース準備
#
# 依存: cargo, npm, cargo-nextest (推奨)

.PHONY: all dev test test-rs test-ts test-e2e bench lint fmt check \
        doc clean release stats mock fuzz audit

# ──────────────────────────────────────────────────────────
# デフォルト: CI と同じ品質チェック
# ──────────────────────────────────────────────────────────
all: fmt lint test
	@echo "✓ All checks passed"

# ──────────────────────────────────────────────────────────
# 開発
# ──────────────────────────────────────────────────────────
dev:
	npm run tauri:dev

mock:
	cargo run -p kaname-mockserver --bin jmap-mock

dev-web:
	npm run dev

# ──────────────────────────────────────────────────────────
# テスト
# ──────────────────────────────────────────────────────────
test: test-rs test-ts

test-rs:
	@command -v cargo-nextest >/dev/null 2>&1 && \
	  cargo nextest run --workspace || \
	  cargo test --workspace

test-ts:
	npm run test:unit

test-e2e:
	npm run test:e2e

test-a11y:
	npm run test:a11y

test-all: test-rs test-ts test-e2e

# ──────────────────────────────────────────────────────────
# コード品質
# ──────────────────────────────────────────────────────────
fmt:
	cargo fmt --all
	@command -v npx >/dev/null && npx prettier --write src/ || true

fmt-check:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	npm run lint 2>/dev/null || true

check: fmt-check lint
	cargo check --workspace

# ──────────────────────────────────────────────────────────
# ドキュメント
# ──────────────────────────────────────────────────────────
doc:
	cargo doc --workspace --no-deps --open

# ──────────────────────────────────────────────────────────
# ベンチマーク
# ──────────────────────────────────────────────────────────
bench:
	cargo bench --workspace

bench-bec:
	cargo bench --bench core_bench -- bec

bench-ai:
	cargo bench --bench core_bench -- ai

# ──────────────────────────────────────────────────────────
# セキュリティ監査
# ──────────────────────────────────────────────────────────
audit:
	cargo audit
	cargo deny check all
	npm audit --omit=dev 2>/dev/null || true

# ──────────────────────────────────────────────────────────
# ファジング (nightly 必要)
# ──────────────────────────────────────────────────────────
fuzz-mime:
	cd fuzz && cargo +nightly fuzz run mime_parser -- -max_total_time=300

fuzz-html:
	cd fuzz && cargo +nightly fuzz run html_sanitizer -- -max_total_time=300

fuzz-prompt:
	cd fuzz && cargo +nightly fuzz run prompt_injection -- -max_total_time=300

fuzz-all:
	$(MAKE) fuzz-mime fuzz-html fuzz-prompt

# ──────────────────────────────────────────────────────────
# リリース
# ──────────────────────────────────────────────────────────
release:
	@echo "バージョン番号を引数で指定してください: make release VERSION=0.4.0"
	@[ -n "$(VERSION)" ] || exit 1
	./scripts/release.sh $(VERSION)

# ──────────────────────────────────────────────────────────
# プロジェクト統計
# ──────────────────────────────────────────────────────────
stats:
	./scripts/stats.sh

stats-json:
	./scripts/stats.sh --json

# ──────────────────────────────────────────────────────────
# クリーン
# ──────────────────────────────────────────────────────────
clean:
	cargo clean
	rm -rf node_modules dist target

clean-docs:
	rm -rf target/doc

# ──────────────────────────────────────────────────────────
# ヘルプ
# ──────────────────────────────────────────────────────────
help:
	@echo "Kaname Makefile"
	@echo ""
	@echo "  make          fmt + lint + test (デフォルト)"
	@echo "  make dev      Tauri 開発サーバー起動"
	@echo "  make mock     JMAP モックサーバー起動"
	@echo "  make test     全テスト (Rust + TypeScript)"
	@echo "  make test-e2e Playwright E2E テスト"
	@echo "  make bench    ベンチマーク"
	@echo "  make audit    セキュリティ監査"
	@echo "  make fuzz-all ファジング (nightly 必要)"
	@echo "  make release VERSION=x.y.z リリース"
	@echo "  make stats    プロジェクト統計"
	@echo "  make doc      ドキュメント生成・表示"
	@echo "  make clean    ビルド成果物削除"

.PHONY: static-check
static-check: ## 静的整合性チェック (cargo不要)
	bash scripts/static-check.sh
