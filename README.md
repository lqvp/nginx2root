# nginx2root（nginx 1.31.8 の脆弱性をローカルで再現するフル PoC パッケージ）

[nginx2root.com](https://nginx2root.com/)（Xint: "NGINX2Root: New Remote Code
Execution Vulnerabilities in nginx"）で報告された **10 件の nginx 脆弱性**
と **Linux kernel SCTP のローカル権限昇格（LPE）** を、1 本のハーネス
（`full-poc.py`）と自己完結型モジュール群（`modules/`）で
**ローカル環境において再現・検証する**ためのリリースパッケージです。

脆弱側 nginx **1.31.8** と修正側 **1.31.9** をソースからビルドして並べ、
同一のトリガを双方に送信することで、修正版だけがクラッシュしないことを差分として
確認できます。

> **免責**: 本パッケージの PoC は検証用に自分の管理下にある環境で実行する
> ことを前提としています。対象が自分の管理下にない環境への実行は行わない
> でください。実行結果は環境依存です（詳細は後述の免責事項）。

---

## 対応 CVE 一覧（10 件 + kernel SCTP LPE）

| CVE | モジュール | 効果（概要） | 修正バージョン |
|-----|-----------|--------------|----------------|
| CVE-2026-123007 | `modules/123007.py`（インライン） | HTTP/2 フロー制御の整数オーバーフロー → 巨大 memcpy → 制御フロー奪取 | 1.31.9 |
| CVE-2026-123634 | `modules/123634.py`（インライン） | resolver の use-after-free（mirror サブリクエスト） | 1.31.9 |
| CVE-2026-123633 | `modules/123633.py`（インライン） | HTTP/2 再利用可能接続の UAF（drain 時） | 1.31.9 |
| CVE-2026-121810 | `modules/121810.py`（インライン） | HTTP/3 QUIC ストリームの UAF（drain 時） | 1.31.9 |
| CVE-2026-113425 | `modules/113425.py`（インライン） | mail proxy auth_http の UAF | 1.31.9 |
| CVE-2026-125283 | `modules/125283.py` | alias + try_files の script underwrite によるバッファオーバーラン | 1.31.9 / 1.30.7 |
| CVE-2026-123640 | `modules/123640.py` | stream ssl_preread の重複 SNI/ALPN 入力検証不足 | 1.31.9 / 1.30.7 |
| CVE-2026-120967 | `modules/120967.py` | stream の SNI 指定時クライアント証明書検証漏れ | 1.31.9 / 1.30.7 |
| CVE-2026-120993 | `modules/120993.py` | PROXY protocol v2 + 動的証明書の NULL 参照 SIGSEGV | 1.31.9 |
| CVE-2026-118899 | `modules/118899.py` | TLS 1.3 request body 読取中の NGX_AGAIN 無限ループ（100% CPU） | 1.31.9 |
| SCTP LPE (kernel) | `modules/sctp_lpe.py` | SCTP send 待ち中の association peeloff による double free / UAF → root | kernel 修正（要検証） |

影響バージョン・CVSS・根本原因（修正コミットハッシュ）などの詳細は
**`docs/` 配下の各文書**を参照してください。

- 技術解説（CVE 別・10 件）: [docs/README.md](docs/README.md)（索引）
- 実証結果（1.31.8 vs 1.31.9 の差分表）: [RESULTS.md](RESULTS.md)
- SCTP LPE の技術メモ: `modules/NOTES-sctp.md`

## 動作要件

- **OS**: Debian 12（検証環境）。Linux kernel 側は SCTP
  （`socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)`）が利用可能なこと
  （`--kernel` 実行時のみ必要）
- **Python**: 3.12（3.9 系でも動作する見込みですが、検証は 3.12 のみ）
- **OpenSSL**: 3.0 系（検証環境は 3.0.22）。ビルドした nginx がリンクする
  OpenSSL のバージョンによっては 120967 / 118899 の再現性が変わります
- **コンパイラ**: gcc（nginx のソースビルドのため。検証環境は gcc 12.2.0）
- **nginx ソース**: 1.31.8（脆弱版）と 1.31.9（修正版）を
  `scripts/build-nginx.sh` でビルドします
- `--kernel` 実行時は SCTP カーネルモジュールと `/proc/slabinfo` の読み取りが
  できる環境が望ましい（`dmesg_restrict` 等によりカーネルログが読めない場合は
  effect=TRIGGERED 止まりになります）

## クイックスタート

```console
# 1) nginx 1.31.8 / 1.31.9（+ ASan 版）をソースからビルド
cd scripts/
./build-nginx.sh                # build/inst-vuln, build/inst-fixed 等を生成
                                # nginx ソースは https://nginx.org/download/ から取得

# 2) 全 CVE を一括実行（--quick --compare）
./run-all.sh                    # 1.31.8 と 1.31.9 を順に実行して差分表示
#    ./run-all.sh --kernel      # SCTP カーネル LPE も実行
#    ./run-all.sh --only 123633,113425   # CVE を絞って実行
```

単体で実行する場合:

```console
python3 full-poc.py              # 1.31.8 に対して 10 件 + kernel を実行
python3 full-poc.py --compare    # 1.31.8 と 1.31.9 を順に実行して差分表示
python3 full-poc.py --quick      # 123007 の完全ラップ（約 111 GB 受信）を省略し
                                 # 小予算の oracle 差分のみ確認
python3 full-poc.py --only 123633,113425
```

### 期待される出力

`run-all.sh`（`--quick --compare`）を実行すると、各 CVE について
`[vuln ]`（1.31.8）と `[fixed]`（1.31.9）の 2 行が表示され、
脆弱側だけで `effect=CRASH` / `effect=VULNERABLE` / `effect=ACCEPT` などの
**効果が発生し、修正側では同一経路を実行しても発生しない**ことが差分として
確認できます。実測値の全容は [RESULTS.md](RESULTS.md) を参照してください。

> **CVE-2026-123007 の注意**: 完全再現には「1 接続あたり約 2^33 個の
> WINDOW_UPDATE（約 111 GB 相当の受信）」が必要です（記事の観測値と一致）。
> `--quick` はこの巨大送信を行わず、小予算の oracle 差分
> （修正版だけが `FLOW_CONTROL_ERROR` で接続を切る）のみを確認します。
> **本パッケージのデフォルトでは `--quick` 相当の小予算のみを実行します。**

## ディレクトリ構成

```
nginx2root/
├── README.md                 # 本ドキュメント（マスター文書）
├── full-poc.py                # 統合ハーネス（全 10 CVE + SCTP kernel）
├── modules/                   # 自己完結モジュール 11 本 + NOTES-*.md + *.result.json
│   ├── 123007.py / 123634.py / 123633.py / 121810.py / 113425.py
│   ├── 125283.py / 123640.py / 120967.py / 120993.py / 118899.py
│   ├── sctp_lpe.py            # SCTP LPE（--kernel）
│   ├── NOTES-*.md              # 各 CVE の技術メモ（実証記録）
│   └── *.result.json           # 各モジュールの実証結果
├── docs/                      # CVE 別の技術解説（NOTES を清書したもの・10 件）
│   └── CVE-2026-XXXXXX.md     # 概要 / 根本原因 / 再現条件 / 観測方法 / 結果
├── RESULTS.md                 # 本環境での実証結果（vuln / fixed の差分表）
├── scripts/
│   ├── build-nginx.sh          # ソースから 1.31.8/1.31.9（+ASan 版、1.30.6/1.30.7）をビルド
│   └── run-all.sh             # full-poc.py --quick --compare で全 CVE を一括実行
├── labs/                      # docker compose による環境再現（CVE 別に分離）
│   └── CVE-2026-XXXX/         # docker-compose.yml + conf/ + 補助サーバ + README.md
└── .gitignore                 # 実行時生成物（__pycache__/ や poc-run-*/ 等）の除外定義
```

- `full-poc.py` は自ディレクトリ直下の `modules/` を参照します
  （`build/` は `scripts/build-nginx.sh` で生成。`--local-bin` で既存の
  nginx バイナリを直接指定することも可能です）
- `modules/*.result.json` と `RESULTS.md`、`modules/NOTES-*.md` は
  **実証記録としてリポジトリに含める成果物**です（`.gitignore` の対象外）
- `labs/` の詳細は [labs/README.md](labs/README.md) を参照

## 実行結果サマリ

本リリース作成環境（Debian 12 / OpenSSL 3.0.22 / Python 3.12、nginx
1.31.8 / 1.31.9 をソースビルド）での実測差分は **[RESULTS.md](RESULTS.md)**
に原文ログ付きでまとめています。要約:

- 123634 / 123633 / 121810 / 113425 / 120993: **1.31.8 で signal 11 の
  worker クラッシュ（CRASH）**、1.31.9 では同一経路を実行してもクラッシュせず
- 123007: quick oracle で 1.31.8 はアンダーフロー検査を通過（ACCEPT）、
  1.31.9 は `FLOW_CONTROL_ERROR` で拒否
- 125283: memmove によるパス文字列のメモリ破壊を観測（ASan 版は
  `negative-size-param` で CRASH）
- 123640: malformed ClientHello が非 default へ振り分けられる（VULNERABLE）
- 120967 / 118899: 本環境の OpenSSL 3.0.22 ではトリガ条件（同期完了 /
  SSL_ERROR_WANT_WRITE）が発生せず、挙動差なし（probe エミュレーションや
  過去実績で脆弱条件側の挙動は検証済み）
- SCTP kernel: `--kernel` で UAF 候補経路に到達（TRIGGERED）

## 免責事項

- **検証環境依存**: 実証結果は Debian 12 / OpenSSL 3.0.22 / Python 3.12 の
  環境で取得したものです。OpenSSL のバージョンやタイミングにより、
  再現性（特に 120967 / 118899 / 121810）は変わります。
- **compose は未テスト**: `labs/` の docker compose 定義は本リリースの
  作成環境に docker がないため未テストです。各 `conf/nginx.conf` は
  ローカル検証で使用したものと同一内容です。
- **攻撃対象は自分の管理下のみで**: 本パッケージの PoC はローカル検証用です。
  実行前に、対象の nginx / kernel が自分の管理下にあることを確認してください。
- CVE-2026-123007 の完全再現（約 111 GB の WINDOW_UPDATE 送信）は
  `--quick` では行いません。完全に再現する場合は `full-poc.py` から
  `--quick` を外して実行してください（時間とネットワーク帯域を大きく消費
  します）。
- RCE（root 権限奪取）の最終段階のヒープ整形は元記事で詳細が省略されて
  いるため、本パッケージの判定は LEAK / CRASH / TRIGGERED までです。
  環境によっては RCE まで到達しません。
