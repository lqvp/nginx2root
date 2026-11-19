#!/usr/bin/env bash
# =============================================================================
# run-all.sh — 全 CVE を full-poc.py --quick --compare で一括実行
# =============================================================================
#
# 前提:
#   * ../build/inst-vuln（nginx 1.31.8）と ../build/inst-fixed（nginx 1.31.9）
#     が存在すること。無い場合は先に scripts/build-nginx.sh を実行してください。
#   * full-poc.py の --only 既定値は全 10 CVE（123007, 123634, 123633, 121810,
#     113425, 125283, 123640, 120967, 120993, 118899）です。
#
# 動作:
#   * --quick       : CVE-2026-123007 の完全再現（1 接続あたり約 2^33 個の
#                     WINDOW_UPDATE ≈ 111 GB 受信）を省略し、小予算の差分確認
#                     （oracle）のみ実行します。巨大送信は行いません。
#   * --compare     : 1.31.8（vuln）と 1.31.9（fixed）を順に実行して差分表示。
#   * 追加の引数はすべて full-poc.py にそのまま渡されます。
#     （例: ./run-all.sh --kernel          # SCTP カーネル LPE も実行
#           ./run-all.sh --only 123633,113425）
#
# 注意:
#   * 各モジュールは nginx の起動・停止を自分で行います（終了後に port の
#     解放を待つため、全体で数分かかることがあります）。
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POC="$RELEASE_ROOT/full-poc.py"

if [ ! -f "$POC" ]; then
    echo "run-all.sh: $POC が見つかりません。リリース構成を確認してください。" >&2
    exit 1
fi

# ビルド成果物の存在チェック（無ければ build-nginx.sh を案内して終了）
missing=0
for d in inst-vuln inst-fixed; do
    if [ ! -x "$RELEASE_ROOT/build/$d/sbin/nginx" ]; then
        echo "run-all.sh: build/$d/sbin/nginx が見つかりません。" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "run-all.sh: 先に scripts/build-nginx.sh を実行してください。" >&2
    echo "            （./scripts/build-nginx.sh で vuln/fixed/ASan 版をビルド）" >&2
    exit 1
fi

echo "[*] nginx バイナリの確認:"
echo "    vuln  = $($RELEASE_ROOT/build/inst-vuln/sbin/nginx -v 2>&1)"
echo "    fixed = $($RELEASE_ROOT/build/inst-fixed/sbin/nginx -v 2>&1)"
echo "[*] full-poc.py --quick --compare を実行します（全 10 CVE）..."
echo

# 全 10 CVE を一括実行（--quick 付きのため 123007 の 111 GB 巨大送信は行わない）。
# CVE 一覧は full-poc.py の --only 既定値と同一（明示してサイド効果を持たせない）。
ALL_CVES="123007,123634,123633,121810,113425,125283,123640,120967,120993,118899"

exec python3 "$POC" --quick --compare --only "$ALL_CVES" "$@"
