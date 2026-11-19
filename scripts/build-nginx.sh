#!/usr/bin/env bash
# =============================================================================
# build-nginx.sh — nginx2root 検証用 nginx のビルド再現スクリプト
# =============================================================================
#
# 本スクリプトは、nginx2root プロジェクトの PoC 検証で実際に使用した
# ビルド構成を再現します（検証環境: Debian 12 / gcc 12.2.0 / OpenSSL 3.0.22）。
#
# 【ソースのダウンロード元】
#   nginx 公式ダウンロードサイト: https://nginx.org/download/
#     - https://nginx.org/download/nginx-1.31.8.tar.gz  （脆弱版）
#     - https://nginx.org/download/nginx-1.31.9.tar.gz  （修正版）
#     - https://nginx.org/download/nginx-1.30.6.tar.gz  （オプション: 脆弱版・旧系列）
#     - https://nginx.org/download/nginx-1.30.7.tar.gz  （オプション: 修正版・旧系列）
#   環境変数 NGX_MIRROR でミラー（例: https://nginx.org/download 以外）に変更可能。
#
# 【ビルド構成（本環境で nginx -V により確認済みのもの）】
#   ./configure --prefix=<build/inst-XXX> \
#     --with-http_ssl_module --with-http_v2_module --with-http_v3_module \
#     --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module \
#     --with-mail --with-mail_ssl_module \
#     --with-debug --with-cc-opt='-O1 -g'
#
# 【生成物（インストール先 prefix）】
#   build/inst-vuln        nginx 1.31.8（脆弱版）
#   build/inst-fixed       nginx 1.31.9（修正版）
#   build/inst-asan-vuln   nginx 1.31.8 + AddressSanitizer
#   build/inst-asan-fixed  nginx 1.31.9 + AddressSanitizer
#   build/inst-vuln1306    nginx 1.30.6（--with-130 オプション時）
#   build/inst-fixed1307   nginx 1.30.7（--with-130 オプション時）
#
# 使い方:
#   ./build-nginx.sh                 # vuln / fixed / asan-vuln / asan-fixed をビルド
#   ./build-nginx.sh --with-130      # 1.30.6 / 1.30.7 も追加ビルド
#   ./build-nginx.sh --only vuln     # vuln だけビルド（vuln|fixed|asan-vuln|asan-fixed|
#                                   #  vuln1306|fixed1307 から選択、カンマ区切り可）
#
# 備考:
#   * ASan 版は make 時にコンパイラ/リンカへ -fsanitize=address を渡します
#     （本環境では --with-cc-opt / --with-ld-opt で指定した実績あり）。
#   * ビルド成果物は release/nginx2root/build/ 配下に置かれ、full-poc.py の
#     pick_local_bins（BUILD / "inst-vuln" 等）から自動検出されます。
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="${NGX_BUILD_ROOT:-$RELEASE_ROOT/build}"
SRC_DIR="$BUILD_ROOT/src"

NGX_MIRROR="${NGX_MIRROR:-https://nginx.org/download}"
VULN_VERSION="${VULN_VERSION:-1.31.8}"
FIXED_VERSION="${FIXED_VERSION:-1.31.9}"
VULN130_VERSION="${VULN130_VERSION:-1.30.6}"
FIXED130_VERSION="${FIXED130_VERSION:-1.30.7}"

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

# -----------------------------------------------------------------------------
# コマンドライン解析
# -----------------------------------------------------------------------------
WITH_130=0
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --with-130) WITH_130=1 ;;
        --only)     ONLY="$2"; shift ;;
        --only=*)   ONLY="${1#--only=}" ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "build-nginx.sh: 不明なオプション: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# ビルド対象の一覧
# -----------------------------------------------------------------------------
declare -a TARGET_NAMES=(
    vuln fixed asan-vuln asan-fixed
    vuln1306 fixed1307
)

want() {
    # $1 = ターゲット名。--only 未指定なら常時 true（ただし 130 系は --with-130 が必要）
    if [ -n "$ONLY" ]; then
        case ",$ONLY," in
            *",$1,"*) return 0 ;;
            *) return 1 ;;
        esac
    else
        case "$1" in
            vuln1306|fixed1307) [ "$WITH_130" -eq 1 ] ;;
            *) return 0 ;;
        esac
    fi
    return 1
}

# -----------------------------------------------------------------------------
# 共通の configure オプション（本環境のビルド構成をそのまま再現）
# -----------------------------------------------------------------------------
NGX_CONFIGURE_FLAGS=(
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_v3_module
    --with-stream
    --with-stream_ssl_module
    --with-stream_ssl_preread_module
    --with-mail
    --with-mail_ssl_module
    --with-debug
)

# ソース tarball の取得（nginx.org/download から）
fetch_source() {
    local ver="$1"
    local tarball="nginx-$ver.tar.gz"
    mkdir -p "$SRC_DIR"
    if [ -f "$SRC_DIR/$tarball" ]; then
        echo "[*] $SRC_DIR/$tarball は既に存在します（再利用）"
    elif [ -d "$SRC_DIR/nginx-$ver" ]; then
        echo "[*] 展開済みソース $SRC_DIR/nginx-$ver があります（tarball は取得不要）"
    else
        echo "[*] $NGX_MIRROR/$tarball をダウンロードします..."
        curl -fL --retry 3 -o "$SRC_DIR/$tarball" "$NGX_MIRROR/$tarball"
    fi
}

# ソースの展開（既に展開済みならスキップ）
extract_source() {
    local ver="$1"
    if [ -d "$SRC_DIR/nginx-$ver" ]; then
        echo "[*] $SRC_DIR/nginx-$ver は展開済みです"
        return
    fi
    echo "[*] nginx-$ver.tar.gz を展開します..."
    tar xzf "$SRC_DIR/nginx-$ver.tar.gz" -C "$SRC_DIR"
}

# 標準ビルド（ASan なし）
#   $1 = バージョン, $2 = インストール先 prefix の相対名（inst-XXX）
build_nginx() {
    local ver="$1" instname="$2"
    local src="$SRC_DIR/nginx-$ver"
    local prefix="$BUILD_ROOT/$instname"
    echo "=============================================="
    echo "[*] ビルド: nginx $ver -> $prefix"
    echo "=============================================="
    fetch_source "$ver"
    extract_source "$ver"
    (
        cd "$src"
        ./configure --prefix="$prefix" \
            "${NGX_CONFIGURE_FLAGS[@]}" \
            --with-cc-opt='-O1 -g'
        make -j"$JOBS"
        make install
    )
    "$prefix/sbin/nginx" -V 2>&1 | sed 's/^/    /'
    echo "[+] 完了: $prefix/sbin/nginx"
}

# ASan ビルド（AddressSanitizer 有効）
#   make に -fsanitize=address を追加する構成。本環境の実績では
#   --with-cc-opt / --with-ld-opt 経由で make の CFLAGS/LDFLAGS に反映。
build_nginx_asan() {
    local ver="$1" instname="$2"
    local src="$SRC_DIR/nginx-$ver"
    local prefix="$BUILD_ROOT/$instname"
    echo "=============================================="
    echo "[*] ビルド(ASan): nginx $ver -> $prefix"
    echo "=============================================="
    fetch_source "$ver"
    extract_source "$ver"
    (
        cd "$src"
        # ASan 版はソースツリーを共有しない（configure が objs/ を再生成するため
        # 通常版と ASan 版で同じソースツリーを再利用すると設定が干渉し得る。
        # 安全のため ASan ビルド前に make clean する）
        make clean >/dev/null 2>&1 || true
        ./configure --prefix="$prefix" \
            "${NGX_CONFIGURE_FLAGS[@]}" \
            --with-cc-opt='-O1 -g -fsanitize=address -fno-omit-frame-pointer -fno-pie' \
            --with-ld-opt='-fsanitize=address -no-pie'
        make -j"$JOBS"
        make install
    )
    echo "[+] 完了(ASan): $prefix/sbin/nginx"
}

mkdir -p "$BUILD_ROOT" "$SRC_DIR"

BUILD_ANY=0

# --- 脆弱版 (1.31.8) → build/inst-vuln ---
if want vuln; then
    build_nginx "$VULN_VERSION" "inst-vuln"
    BUILD_ANY=1
fi

# --- 修正版 (1.31.9) → build/inst-fixed ---
if want fixed; then
    build_nginx "$FIXED_VERSION" "inst-fixed"
    BUILD_ANY=1
fi

# --- 脆弱版 ASan (1.31.8) → build/inst-asan-vuln ---
if want asan-vuln; then
    build_nginx_asan "$VULN_VERSION" "inst-asan-vuln"
    BUILD_ANY=1
fi

# --- 修正版 ASan (1.31.9) → build/inst-asan-fixed ---
if want asan-fixed; then
    build_nginx_asan "$FIXED_VERSION" "inst-asan-fixed"
    BUILD_ANY=1
fi

# --- オプション: 旧系列 脆弱版 (1.30.6) → build/inst-vuln1306 ---
if want vuln1306; then
    build_nginx "$VULN130_VERSION" "inst-vuln1306"
    BUILD_ANY=1
fi

# --- オプション: 旧系列 修正版 (1.30.7) → build/inst-fixed1307 ---
if want fixed1307; then
    build_nginx "$FIXED130_VERSION" "inst-fixed1307"
    BUILD_ANY=1
fi

if [ "$BUILD_ANY" -eq 0 ]; then
    echo "build-nginx.sh: 実行対象がありません（--only の指定を確認してください）" >&2
    exit 1
fi

echo "=============================================="
echo "[+] ビルド完了。インストール先:"
echo "    $BUILD_ROOT/inst-vuln/sbin/nginx         (1.31.8 脆弱版)"
echo "    $BUILD_ROOT/inst-fixed/sbin/nginx        (1.31.9 修正版)"
echo "    $BUILD_ROOT/inst-asan-vuln/sbin/nginx    (1.31.8 ASan)"
echo "    $BUILD_ROOT/inst-asan-fixed/sbin/nginx   (1.31.9 ASan)"
[ "$WITH_130" -eq 1 ] && echo "    $BUILD_ROOT/inst-vuln1306/sbin/nginx      (1.30.6 脆弱版・旧系列)
    $BUILD_ROOT/inst-fixed1307/sbin/nginx     (1.30.7 修正版・旧系列)"
echo "=============================================="
