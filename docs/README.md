# nginx2root 技術解説ドキュメント（docs/）

本ディレクトリは、nginx2root プロジェクトが対象とした **CVE 10 件**の技術解説を
収録する。各文書は `modules/NOTES-*.md`（および該当するモジュールの docstring と
`*.result.json`）をベースに、以下の観点で清書したものである。

1. **CVE 概要**（深刻度・影響バージョン・影響構成・緩和策）
2. **根本原因**（該当ソースコードと修正コミットハッシュ）
3. **再現の前提設定**（nginx.conf・専有ポート・証明書・補助サーバ）
4. **観測方法**（oracle / 判定基準 / 再現手順）
5. **本プロジェクトでの結果**（`modules/*.result.json` の要点）

## CVE 一覧（10 件）

| CVE | 題目 | 影響バージョン | 修正 | 結果（vuln / fixed） | 文書 |
|---|---|---|---|---|---|
| CVE-2026-123007 | HTTP/2 フロー制御の整数アンダーフロー（CVSSv4 9.2 / CWE-191） | 1.9.5–1.31.8 | 1.31.9 | quick: ACCEPT / FLOWCTRL、112GiB: **CRASH** / FLOWCTRL | [CVE-2026-123007.md](CVE-2026-123007.md) |
| CVE-2026-123634 | resolver の UAF（mirror サブリクエスト） | 1.13.4–1.31.8 | 1.31.9 | **CRASH** / TRIGGERED | [CVE-2026-123634.md](CVE-2026-123634.md) |
| CVE-2026-123633 | HTTP/2 reusable 接続の UAF（drain 時） | 1.19.7–1.31.8 | 1.31.9 | **CRASH** / TRIGGERED | [CVE-2026-123633.md](CVE-2026-123633.md) |
| CVE-2026-121810 | HTTP/3 QUIC ストリーム生成中の drain による親接続 UAF | 1.25.0–1.31.8 | 1.31.9 | **CRASH**（5/5） / TRIGGERED | [CVE-2026-121810.md](CVE-2026-121810.md) |
| CVE-2026-113425 | mail proxy auth_http の UAF | 0.5.15–1.31.8 | 1.31.9 | **CRASH**（40/40） / TRIGGERED（0/40） | [CVE-2026-113425.md](CVE-2026-113425.md) |
| CVE-2026-125283 | alias + try_files の script underwrite バッファオーバーラン | ≤1.31.8 / ≤1.30.6 | 1.31.9 / 1.30.7 | TRIGGERED（メモリ破壊観測）/ TRIGGERED。ASan 版: **CRASH** | [CVE-2026-125283.md](CVE-2026-125283.md) |
| CVE-2026-123640 | stream ssl_preread の入力検証不足（SNI/ALPN スマグリング） | ≤1.31.8 / ≤1.30.6 | 1.31.9 / 1.30.7 | **VULNERABLE**（非 default 振り分け）/ TRIGGERED | [CVE-2026-123640.md](CVE-2026-123640.md) |
| CVE-2026-120967 | stream の SNI 指定時クライアント証明書検証漏れ | ≤1.31.8 / ≤1.30.6 | 1.31.9 / 1.30.7（`77f90f1c`） | VERIFIED（同期完了未発生、probe エミュレーションで差を示す） | [CVE-2026-120967.md](CVE-2026-120967.md) |
| CVE-2026-120993 | PROXY protocol v2 + 動的証明書の NULL 参照 | 1.31.4–1.31.8 | 1.31.9 | **CRASH**（signal 11 / ASan SEGV 0x88） / TRIGGERED | [CVE-2026-120993.md](CVE-2026-120993.md) |
| CVE-2026-118899 | TLS 1.3 request body 読取中の NGX_AGAIN 無限ループ | ≤1.31.8 | 1.31.9（`2b129b93`、1.30.7） | **未再現**（挙動差なし、utime 増分 0.0） | [CVE-2026-118899.md](CVE-2026-118899.md) |

## 備考

- 検証環境: Debian 12 / OpenSSL 3.0.22 / Python 3.12。nginx は
  `scripts/build-nginx.sh` の構成でソースからビルドした
  1.31.8（vuln）と 1.31.9（fixed）、および ASan 版（必要に応じて
  1.30.6 / 1.30.7）。
- CVE-2026-120967 は OpenSSL の内部タイミング（初回ハンドラ呼び出し内での
  ハンドシェイク同期完了）に依存するため、実バイナリ 6 種では VERIFIED と
  なり、プローブビルドによる同期完了エミュレーションで挙動差を実証している。
- CVE-2026-118899 はトリガ条件（body 読取中の SSL_ERROR_WANT_WRITE）が
  OpenSSL 3.0.22 では発生せず、挙動差なしと正直に記録している。
- Linux kernel 側の SCTP UAF（`modules/sctp_lpe.py`）については本ディレクトリの
  対象外（`modules/NOTES-sctp.md` を参照）。
