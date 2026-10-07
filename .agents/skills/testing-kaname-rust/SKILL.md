---
name: testing-kaname-rust
description: How to verify Kaname's Rust crates end-to-end — cargo --offline when the registry is populated (preferred; proves parse()/Envelope wiring), else rustc --test extraction harnesses + e2e-mock.html IPC injection for UI golden paths.
---

# Testing Kaname Rust crates (cargo --offline preferred)

**UPDATE (r168+):** `~/.cargo/registry` is now fully populated (501 crates). `cargo build --offline -p kaname-render` and `cargo test --offline -p kaname-render` both work — use them FIRST; they cover `parse()`/`Envelope` wiring that extraction harnesses cannot see (r168 found 528 `has_*(bytes)` undefined-variable errors invisible to every prior harness round). `kaname-ui` still fails here (dep build script needs `cmake`); `kaname-screen`, `kaname-render` build fine. Restore `Cargo.lock` after builds (`git checkout Cargo.lock`) if cargo touches it.

If the registry is ever empty again, fall back to the rustc recipe below.

## Track A0 — real parse() Envelope verification (preferred when cargo works)

```bash
cargo build --offline -p kaname-render   # produces target/debug/libkaname_render.rlib
cat > /tmp/real_parse.rs <<'EOF'
extern crate kaname_render;
use kaname_render::parse;
use std::fs;
fn main() {
    let raw = fs::read("fixture.eml").unwrap();
    let env = parse(&raw).unwrap();
    assert!(env.<flag>);  // Envelope bool, e.g. env.addr_hash_local
}
EOF
rustc --edition 2021 /tmp/real_parse.rs \
  --extern kaname_render=target/debug/libkaname_render.rlib \
  --extern kaname_screen=target/debug/libkaname_screen.rlib \
  -L target/debug/deps -o /tmp/real_parse && /tmp/real_parse
```

This proves the whole detector→parse()→Envelope wiring for real — do it per round on the round's .eml fixtures.

## Track A — compile module test suites directly with rustc (fallback / no registry)

Many `kaname-render` modules are self-contained (std + serde only, no `crate::` refs). For those:

```bash
# zero-dep module — run verbatim
rustc --edition 2021 --test crates/kaname-render/src/magic_bytes.rs -o /tmp/kv/mb_test && /tmp/kv/mb_test

# serde-only module — mechanically strip serde, diff-verify nothing else changed
sed -E -e '/^use serde/d' \
  -e 's/, *Serialize//g' -e 's/Serialize, *//g' -e 's/\bSerialize\b//g' \
  -e 's/, *Deserialize//g' -e 's/Deserialize, *//g' -e 's/\bDeserialize\b//g' \
  -e 's/, +\)/)/g' src/svg_guard.rs > /tmp/kv/stripped/svg_guard.rs
diff src/svg_guard.rs /tmp/kv/stripped/svg_guard.rs   # must show ONLY serde lines
rustc --edition 2021 --test /tmp/kv/stripped/svg_guard.rs -o /tmp/kv/svg_test
```

This works for: `magic_bytes`, `metadata_check`, `svg_guard`, `html_smuggling`, `calendar_guard`, `quishing` — their `#[cfg(test)] mod tests` run for real.

### Module gotchas

- `svg_guard`, `calendar_guard` reference `kaname_screen::` types → build `kaname-screen` once as a real rlib and pass `--extern`:
  ```bash
  sed <same strip> crates/kaname-screen/src/lib.rs > /tmp/kv/stripped/kaname_screen.rs
  rustc --edition 2021 --crate-type rlib --crate-name kaname_screen \
    /tmp/kv/stripped/kaname_screen.rs -o /tmp/kv/libkaname_screen.rlib
  rustc --edition 2021 --test svg_guard.rs --extern kaname_screen=/tmp/kv/libkaname_screen.rlib ...
  ```
- `quishing.rs` uses `#[derive(thiserror::Error)]` + `#[error]` → hand-expand the enum into a manual `impl std::fmt::Display + std::error::Error` (pure mechanical expansion, diff to prove).
- `html_smuggling.rs` string literals contain `\u{...}` escapes — never retype test vectors by hand; always copy bytes verbatim.

## Track B — verbatim extraction harness for cross-module code

`lib.rs` orchestration (e.g. `scan_attachment_bytes`) and `commands.rs` helpers depend on several modules + crate paths. Build a harness crate:

```rust
#![allow(dead_code)]
mod kaname_render {
    pub mod magic_bytes { include!("/tmp/kv/inc/magic_bytes.rs"); }
    pub mod svg_guard   { include!("/tmp/kv/inc/svg_guard.rs"); }
    pub mod quishing    { include!("/tmp/kv/inc/quishing_patched.rs"); }
    // contiguous self-contained ranges of lib.rs can be included wholesale:
    include!("/tmp/kv/inc/html_text_cluster.rs"); // html_to_text + helpers
}
use kaname_render::*;   // lets verbatim `magic_bytes::foo` refs resolve
// then splice verbatim item-level ranges (structs, fns) from lib.rs/commands.rs
```

Gotchas:
- `include!` inside `mod x { ... }` needs a trailing `;` after the `include!(...)` call.
- Files starting with `//!` inner doc comments break inside braced mods → pre-copy with `sed 's|^//!|//|'`.
- Whole contiguous *item* ranges from `lib.rs` can be `include!`d directly inside `mod kaname_render` (they become `kaname_render::html_to_text` etc. — matching how `commands.rs` paths resolve). Grep the range for `crate::`/`ammonia`/`regex`/cross-item refs first — the `html_to_text` cluster (ExtractedBodyText + all `has_*` helpers) is fully std-only.
- Mid-function blocks (e.g. the `render_risks.push(...)` if-statements inside `analyze_raw_email`) can't be `include!`d at item position — generate the harness file with a python script that splices `sed -n 'A,Bp'` output into a template at a marker, so the code is byte-identical to source. Wrap it in a fn whose locals use the SAME names (`html_extract`, `analysis_text`, `render_risks`) so the verbatim block compiles unchanged.
- `commands.rs` helper fns reference `kaname_render::quishing::...` verbatim — satisfied automatically by the harness mod name.

Always diff-check that extracted code is verbatim (`diff <(sed -n 'A,Bp' src) <(extracted)`) and say so in the report — the guarantee is "logic untouched, only serde/thiserror mechanics removed".

## Track C — UI golden path without a backend

`npm run dev` (vite :1420) runs the SolidJS shell fine. With no Tauri runtime it shows a styled 起動エラー (`TypeError ... transformCallback`) + 再起動 — graceful, not a hang.

To exercise real UI flows, create `e2e-mock.html` at the repo root (untracked, delete after):

```html
<script>/* install window.__TAURI_INTERNALS__ — copy the structure from
  e2e/tauri-mock.ts: transformCallback/callbacks/invoke/plugin:event|listen */</script>
<script type="module" src="/src/main.tsx"></script>
<body><div id="root"></div></body>  <!-- REQUIRED: main.tsx does getElementById("root") -->
```

Then `http://localhost:1420/e2e-mock.html` drives the real components (`Inbox`, `EmlImport`, …) with mock IPC responses. Put the *real* warning strings from `commands.rs` into `render_risks`/`attachments[].risks` to prove the display pipeline renders them verbatim. `mail_import_eml` returns the same shape as `mail_open` (`OpenedEmail`).

**Display-surface routing**: Inbox mail-detail only renders attachment risks for `is_dangerous=true` attachments (`Inbox.tsx` filters `a.is_dangerous` in the "⚠ 危険な添付" section); the plain attachment list shows filenames only. **Caution-tier** attachment risks (`is_dangerous=false`) — ICS MalformedStructure/ExternalAttachUri, metadata, nested .eml, encrypted ZIP — are produced in the data but only visible via **EmlImport** (`mail_import_eml` result lists every `a.risks` under a `問題なし` badge). Always verify caution-tier attachment warnings through the EmlImport surface.

## Screenshot/report

`screencapture -x /tmp/evidence/x.png` on macOS. Maximize Chrome via
`osascript -e 'tell application "Google Chrome" to set bounds of window 1 to {0,0,1600,1200}'`
(never xdotool/super-key tiling). Report honestly which layers are unverified (`analyze_raw_email` orchestration, serde wire shapes, real `tauri dev`) and ask the user for a crates.io-reachable run of `cargo nextest run --workspace`.

Working example harness: `/tmp/kv/harness.rs` (regenerate per-branch — line ranges shift).

## /tmp/kv/inc/ module copies must be refreshed when the module changes

The cumulative harness `include!`s `/tmp/kv/inc/quishing.rs` etc. — these are STRIPPED COPIES that go stale when the PR adds code to that module (round 35: is_numeric_ip_host added to quishing.rs → stale include produced a false test failure). Regenerate with this exact strip procedure:

```python
import re
s = open(src).read()
s = re.sub(r'^use serde[^;]*;\n', '', s, flags=re.M)   # serde use lines
s = re.sub(r'\bSerialize\b|\bDeserialize\b', '', s)     # derive tokens (word-boundary)
s = re.sub(r',(?:\s*,)+', ',', s)                        # collapse ", ,"
s = re.sub(r',\s*\)', ')', s); s = re.sub(r'\(\s*,', '(', s)
s = re.sub(r'^//!', '//', s, flags=re.M)                # inner doc comments
# new deps appearing later may also need stripping, e.g. thiserror:
s = s.replace('#[derive(Debug, thiserror::Error)]', '#[derive(Debug)]')
s = re.sub(r'^\s*#\[error\([^\]]*\)\]\n', '', s, flags=re.M)
```

Check which path the harness actually includes (`grep 'include!' harness_rNN.rs`) — `/tmp/kv/inc/quishing.rs` vs `quishing_stripped.rs` are different files. If a NEW detector's test fails AND the PR's own verbatim test fails identically, suspect stale include BEFORE suspecting product bug — diff the include against current source.
