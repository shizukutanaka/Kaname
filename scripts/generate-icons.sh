#!/usr/bin/env bash
# scripts/generate-icons.sh
# SVG ソースから全プラットフォーム向けアイコンを生成する。
#
# 必要ツール: rsvg-convert (librsvg), iconutil (macOS), convert (ImageMagick)
#
# 出力:
#   src-tauri/icons/
#     icon.icns        # macOS 用
#     icon.ico         # Windows 用
#     128x128.png      # Linux 用
#     128x128@2x.png   # Linux Retina 用
#     32x32.png        # Tauri 標準

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

SRC_SVG="public/app-icon.svg"
OUT_DIR="src-tauri/icons"
mkdir -p "$OUT_DIR"

if [[ ! -f "$SRC_SVG" ]]; then
    echo "Error: $SRC_SVG not found" >&2
    exit 1
fi

# rsvg-convert チェック
if ! command -v rsvg-convert >/dev/null 2>&1; then
    echo "rsvg-convert がありません。代替方法:"
    echo "  macOS:  brew install librsvg"
    echo "  Linux:  apt install librsvg2-bin"
    echo "  代替:   tauri icon --help  (Tauri が自動生成)"
    exit 1
fi

# 各サイズで PNG 生成
for size in 32 128 256 512 1024; do
    rsvg-convert -w $size -h $size "$SRC_SVG" -o "$OUT_DIR/${size}x${size}.png"
    echo "  ✓ ${size}x${size}.png"
done

# Retina (2x)
rsvg-convert -w 256 -h 256 "$SRC_SVG" -o "$OUT_DIR/128x128@2x.png"

# Windows ICO (128x128 を埋め込み)
if command -v convert >/dev/null 2>&1; then
    convert "$OUT_DIR/16x16.png" "$OUT_DIR/32x32.png" "$OUT_DIR/64x64.png" \
            "$OUT_DIR/128x128.png" "$OUT_DIR/256x256.png" \
            "$OUT_DIR/icon.ico" 2>/dev/null || \
    convert "$OUT_DIR/256x256.png" "$OUT_DIR/icon.ico"
    echo "  ✓ icon.ico"
fi

# macOS ICNS (iconset → icns)
if command -v iconutil >/dev/null 2>&1; then
    ICONSET="$OUT_DIR/icon.iconset"
    mkdir -p "$ICONSET"
    cp "$OUT_DIR/16x16.png"   "$ICONSET/icon_16x16.png" 2>/dev/null || rsvg-convert -w 16 "$SRC_SVG" -o "$ICONSET/icon_16x16.png"
    cp "$OUT_DIR/32x32.png"   "$ICONSET/icon_32x32.png"
    cp "$OUT_DIR/32x32.png"   "$ICONSET/icon_16x16@2x.png"
    cp "$OUT_DIR/128x128.png" "$ICONSET/icon_128x128.png"
    cp "$OUT_DIR/256x256.png" "$ICONSET/icon_128x128@2x.png"
    cp "$OUT_DIR/256x256.png" "$ICONSET/icon_256x256.png"
    cp "$OUT_DIR/512x512.png" "$ICONSET/icon_256x256@2x.png"
    cp "$OUT_DIR/512x512.png" "$ICONSET/icon_512x512.png"
    cp "$OUT_DIR/1024x1024.png" "$ICONSET/icon_512x512@2x.png"
    iconutil -c icns "$ICONSET" -o "$OUT_DIR/icon.icns"
    rm -rf "$ICONSET"
    echo "  ✓ icon.icns"
fi

# トレイアイコン (テンプレート画像、macOS 用)
if [[ -f "public/tray-icon.svg" ]]; then
    rsvg-convert -w 18 -h 18 "public/tray-icon.svg" -o "$OUT_DIR/tray-icon.png"
    rsvg-convert -w 36 -h 36 "public/tray-icon.svg" -o "$OUT_DIR/tray-icon@2x.png"
    echo "  ✓ tray-icon.png + @2x"
fi

echo ""
echo "✓ 全アイコン生成完了 → $OUT_DIR/"
ls -la "$OUT_DIR/"
