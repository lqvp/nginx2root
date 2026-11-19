# labs/ — docker compose による CVE 再現環境一式

nginx2root で扱う 10 CVE の docker compose 再現ラボ。
各ディレクトリに `docker-compose.yml` (nginx-vuln = nginx:1.31.8 /
nginx-fixed = nginx:1.31.9)、`conf/nginx.conf` (モジュールが生成する conf と同一
内容)、必要な補助サーバ (`aux/`)、攻撃クライアント (`poc.py`)、
`README.md` (手順と期待される観測) を格納する。

## 一覧

| CVE | 内容 | lab ディレクトリ | ポート (vuln) | aux |
|-----|------|------------------|---------------|-----|
| CVE-2026-123007 | HTTP/2 フロー制御整数アンダーフロー | CVE-2026-123007/ | 18443 | なし |
| CVE-2026-123633 | HTTP/2 reusable 接続 UAF (drain 時) | CVE-2026-123633/ | 18444/18445 | HTTP バックエンド (19000) |
| CVE-2026-123634 | resolver UAF (mirror サブリクエスト) | CVE-2026-123634/ | 18445 | DNS (15353/udp) + HTTP バックエンド (19000) |
| CVE-2026-121810 | HTTP/3 (QUIC) 親接続 UAF | CVE-2026-121810/ | 18447/tcp + 18446/udp | なし (自己 proxy_pass) |
| CVE-2026-113425 | mail proxy auth_http UAF | CVE-2026-113425/ | 21110/21143/21025 | auth_http (19001) + POP3 バックエンド (21210) |
| CVE-2026-125283 | alias + try_files script underwrite | CVE-2026-125283/ | 18448 | なし |
| CVE-2026-123640 | stream ssl_preread ClientHello 振り分け差分 | CVE-2026-123640/ | 18449 | 振り分け判定バックエンド (19010) |
| CVE-2026-120967 | stream SNI 指定時クライアント証明書検証漏れ | CVE-2026-120967/ | 18450 | 上流エコー (19012) |
| CVE-2026-120993 | PROXY v2 + 動的証明書 NULL 参照 | CVE-2026-120993/ | 18451 | 素の TCP 上流 (19011) |
| CVE-2026-118899 | TLS 1.3 body 読取中の NGX_AGAIN ループ | CVE-2026-118899/ | 18452 | バックエンドモック (19002) |

## 共通仕様

- `nginx-fixed` のホスト側ポートは vuln 側 +10000 (例: 18443 → 28443)。
- 補助サーバが必要な lab では `network_mode: service:<nginx>` で aux コンテナ
  (python:3.11-slim) を nginx と同一ネットワーク名前空間で起動する。
  これにより conf は 127.0.0.1 宛先のまま動作する。
- conf のパスはコンテナ内パス (/etc/nginx/certs, /var/log/nginx,
  /var/cache/nginx/*) に置換し、listen アドレスは 127.0.0.1 固定を外し、
  `user nginx;` を追記している (公式イメージの実行ユーザに合わせるため)。
- 証明書 certs/ は検証用に新規生成した自己署名テスト証明書。

## 免責 (重要)

- **本リポジトリの作成環境には docker がないため、すべての compose 定義は
  未テスト。**
- 各 `conf/nginx.conf` はローカル検証 (`scripts/build-nginx.sh` でビルドした
  nginx 1.31.8 / 1.31.9) で使用したものと同一内容である
  (差し替えは上記パス置換のみ)。
- CVE-2026-113425 のみ mail モジュール (--with-mail) を必要とするため、
  公式イメージのビルド構成次第で起動しない可能性がある (各 lab の README 参照)。
- 攻撃クライアントの完全自動再現は host 側で `modules/<cve>.py` を使う手順を
  基本とする (nginx の起動・停止をモジュール自身が管理するため、docker compose
  との併用時はポート衝突に注意)。抽出が容易なもののみ各 lab に `poc.py`
  (--target 指定) を添付した (125283 / 123640 / 113425 / 123634)。
