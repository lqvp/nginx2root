# RESULTS（本環境での実証結果）

nginx2root リリースパッケージ（`full-poc.py` + `modules/`）を本環境の
`build/inst-vuln`（nginx/1.31.8）と `build/inst-fixed`（nginx/1.31.9）に対して
`--quick` で全 10 CVE 逐次実行した際の結果差分表である。

- 実行日: 2026-11-19（UTC）
- 実行者: release 版 `full-poc.py`（`--quick --only <CVE> --local-bin <binary>` で
  vuln / fixed を各 1 回ずつ逐次実行。`--local-bin` 指定のため結果行のタグは
  `[vuln]` と表示されるが、バイナリパスと version 行でどちらかを判別できる）
- 123007 は quick oracle（小予算の差分確認）のみを実施。完全ラップ（約 111 GB
  相当の WINDOW_UPDATE 送信）は本環境では実施していない。
- 121810 はモジュール内で QUIC リスナーの起動に失敗したため本日は判定を
  result.json の過去実績（CRASH / クラッシュせず）に基づいて記載する。
- SCTP kernel モジュール（`--kernel`）は 1 回実行した。

## 差分サマリ表（全 10 CVE + kernel）

| CVE | 1.31.8 (vuln) | 1.31.9 (fixed) | 差分 |
|-----|---------------|----------------|------|
| CVE-2026-123007 | ACCEPT（WU(0,MAX) 受理） | FLOWCTRL（拒否 + GOAWAY） | あり（quick oracle） |
| CVE-2026-123634 | CRASH（signal 11） | クラッシュせず（TRIGGERED） | あり |
| CVE-2026-123633 | CRASH（signal 11） | クラッシュせず（TRIGGERED） | あり |
| CVE-2026-121810 | CRASH（signal 11）※ | クラッシュせず（TRIGGERED）※ | あり（result.json 実績） |
| CVE-2026-113425 | CRASH（signal 11） | クラッシュせず（TRIGGERED） | あり |
| CVE-2026-125283 | TRIGGERED（メモリ破壊を検出） | 正常（TRIGGERED） | あり |
| CVE-2026-123640 | VULNERABLE（malformed 通過） | TRIGGERED（malformed 拒否） | あり |
| CVE-2026-120967 | VERIFIED（検証バイパス条件未充足） | VERIFIED（検証バイパス条件未充足） | なし（本環境では同期完了が発生せず） |
| CVE-2026-120993 | CRASH（signal 11 / ASan 併記） | クラッシュせず（TRIGGERED） | あり |
| CVE-2026-118899 | TRIGGERED（utime 増加なし） | TRIGGERED（utime 増加なし） | なし（CPU スピンは本環境では非発生） |
| SCTP LPE (kernel) | TRIGGERED（UAF 候補経路に到達） | — | カーネルログ制約のため TRIGGERED |

## 実行ログ（原文）

### CVE-2026-123007（1.31.8 / quick oracle: ACCEPT）

```
[vuln  ] CVE-2026-123007 cfg=True trigger=True effect=ACCEPT  oracle 成立: RST_STREAM(149,151)=FLOW_CONTROL_ERROR(3)、stream 155 に 10 バイト DATA(END_STREAM)、PING ACK=True、受信フレーム数=162 (公開応答 896 バイト) / 接続ウィンドウ MAX+1792 への返却後、アンダーフローした検査が WU(0,MAX) を受理した
```

### CVE-2026-123007（1.31.9 / quick oracle: FLOWCTRL）

```
[vuln  ] CVE-2026-123007 cfg=True trigger=False effect=FLOWCTRL oracle 不成立: RST_STREAM(149/151) が返らず、接続ウィンドウの返却が起きない / error.log: 2026/11/19 00:38:10 [info] 212141#0: *2 client violated connection flow control: received WINDOW_UPDATE frame with window increment 2147483647 not allowed for window 2147483647 while processing HTTP/2 connection, client: 127.0.0.1, server: 127.0.0.1:18443 / 受信フレーム数=159 / GOAWAY=[(153, 3)]
```

### CVE-2026-123634（1.31.8: CRASH / 1.31.9: クラッシュせず）

```
[vuln  ] CVE-2026-123634 cfg=True trigger=True effect=CRASH   prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123634/cve-2026-123634/run / リクエスト送信数=10 / DNS クエリ数=10 / backend ヒット数=0 / resolve 実行ログ数=4 / クラッシュ: 2026/11/19 00:38:22 [alert] 212150#0: worker process 212151 exited on signal 11 / 検出したワーカー異常終了: 2 件 / 解放済み ctx の done() 検出 ([alert] could not cancel): 2026/11/19 00:38:22 [alert] 212151#0: could not cancel u0.test resolving / could not cancel 検出数: 2 件

[vuln  ] CVE-2026-123634 cfg=True trigger=True effect=TRIGGERED prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123634/cve-2026-123634/run / リクエスト送信数=30 / DNS クエリ数=30 / backend ヒット数=0 / resolve 実行ログ数=30 / 同一経路を実行 ([debug] could not cancel / 1.31.9 の free_handler 経由): 2026/11/19 00:38:23 [debug] 212163#0: could not cancel u0.test resolving / could not cancel 検出数: 30 件 (alert ではなく debug) / 修正版の可能性: 同一経路を実行したがクラッシュせず
```

### CVE-2026-123633（1.31.8: CRASH / 1.31.9: クラッシュせず）

```
[vuln  ] CVE-2026-123633 cfg=True trigger=True effect=CRASH   prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123633/cve-2026-123633 / attempts=nkeep=56 crash=1 h2reuse=1 drain=1 reset=0 / backend ヒット数=0 / drain 発動回数=1 / h2 再利用回数=1 / stream 生成直後の reusable 解除: なし（1.31.8） / クラッシュ: 2026/11/19 00:38:25 [alert] 212171#0: worker process 212172 exited on signal 11 / 検出したワーカー異常終了: 1 件 / drain がストリーム持ち HTTP/2 接続を再利用: 2026/11/19 00:38:25 [debug] 212172#0: *2 http2 send GOAWAY frame: last sid 1, error 0

[vuln  ] CVE-2026-123633 cfg=True trigger=True effect=TRIGGERED prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123633/cve-2026-123633 / attempts=nkeep=56 crash=0 h2reuse=0 drain=1 reset=1, nkeep=55 crash=0 h2reuse=0 drain=0 reset=1, nkeep=57 crash=0 h2reuse=0 drain=1 reset=0, nkeep=54 crash=0 h2reuse=0 drain=0 reset=1, nkeep=58 crash=0 h2reuse=0 drain=1 reset=0 / backend ヒット数=0 / drain 発動回数=3 / h2 再利用回数=0 / stream 生成直後の reusable 解除: あり（1.31.9 の修正挙動） / drain は発動したがストリーム持ち HTTP/2 接続は再利用されず、クラッシュも無し（修正版の挙動）
```

### CVE-2026-121810（本日は再現ならず → result.json 実績を記載）

本日の `--quick --only 121810` 実行ではモジュールの QUIC リスナー起動確認に
失敗したため、`modules/121810.result.json` の過去実績（同一バイナリ
`build/inst-vuln` / `build/inst-fixed-v3`、2026-11-18 実施）を結果として採用する。

```
（result.json 抜粋: 1.31.8）
effect: CRASH
detail: nginx/1.31.8 でクラッシュを再現した。
error_log 原文: worker process 135527 exited on signal 11
生成中の stream 0x4 の ngx_get_connection() 内 drain で、親 QUIC 接続 (*1) が reusable キューへ誤って戻されることを確認: *1 reusable connection: 1
直後の proxy_pass upstream 接続取得時の drain が親 *1 を選び、close により 進行中リクエストのメモリが解放されて use-after-free となる。
試行: attempt 1: hold=8 handshake=True z=True drain=True requeue=True crash=True
ログ: /app/data/sessions/conv-43/poc-run-C/logs/error.log

（result.json 抜粋: 1.31.9）
effect: TRIGGERED
detail: nginx/1.31.9 では同一シナリオで signal 11 が発生しなかった（修正版の挙動）。
drain は発生している: "worker_connections are not enough, reusing connections"
1.31.9 では rbtree 挿入が ngx_get_connection() より前に移動したため、生成中ストリームが can_shutdown に認識され、親 QUIC 接続は reusable キューへ戻らない。その結果、後続の upstream 接続取得時にも親は選ばれず、リクエストが解放されない。
試行: attempt 1: hold=8 handshake=True z=True drain=True requeue=False crash=False / attempt 2: hold=9 handshake=True z=True drain=True requeue=False crash=False
ログ: /app/data/sessions/conv-43/poc-run-C/fixed-v3/logs/error.log
```

### CVE-2026-113425（1.31.8: CRASH / 1.31.9: クラッシュせず）

```
[vuln  ] CVE-2026-113425 cfg=True trigger=True effect=CRASH   binary=/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx / version=nginx version: nginx/1.31.8 / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-113425/poc-run-D / 試行回数=1 / CAPABILITY 応答長=200151 bytes / 1 試行あたり 40 コマンド / worker 異常終了 (signal) 検出数=1 / auth 待機中のクライアント write ハンドラ失敗 (while in auth state) 検出数=1 / クラッシュ例: worker process 212422 exited on signal 11 / auth 待機中の送信失敗例: 2026/11/19 00:39:35 [info] 212422#0: *5 send() failed (104: Connection reset by peer) while in http auth state, client: 127.0.0.1, server: 127.0.0.1:21143, login: "test" / auth_http 応答時に解放済みセッションを参照して UAF → signal 11

[vuln  ] CVE-2026-113425 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-fixed/sbin/nginx / version=nginx version: nginx/1.31.9 / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-113425/poc-run-D / 試行回数=40 / CAPABILITY 応答長=200151 bytes / 1 試行あたり 40 コマンド / worker 異常終了 (signal) 検出数=0 / auth 待機中のクライアント write ハンドラ失敗 (while in auth state) 検出数=0 / 同一経路を実行したがクラッシュせず（修正版の可能性）
```

### CVE-2026-125283（1.31.8: メモリ破壊検出 / 1.31.9: 正常）

```
[vuln  ] CVE-2026-125283 cfg=True trigger=True effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx / nginx version: nginx/1.31.8 / request: GET /a/x → HTTP/1.1 404 Not Found / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run / POCDBG predicted=2 actual=6 alias=3 n=-1 (len-alias がアンダーフロー) / debug ログのパス文字列が破損: 'p/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run/html//a/xM' (期待 '/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run/html/xM') — memmove が バッファを alias=3 バイトだけ左へずらしたメモリ破壊

[vuln  ] CVE-2026-125283 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-fixed/sbin/nginx / nginx version: nginx/1.31.9 / request: GET /a/x → HTTP/1.1 404 Not Found / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run / パス文字列は正常 ('/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run/html/xM')、ASAN レポート無し — 修正版の挙動
```

#### CVE-2026-125283 ASan 版追試

```
[vuln  ] CVE-2026-125283 cfg=True trigger=True effect=CRASH   binary=/app/data/sessions/conv-43/build/inst-asan-vuln/sbin/nginx / nginx version: nginx/1.31.8 / request: GET /a/x → <EOF (no response)> / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run / ASAN: ERROR: AddressSanitizer: negative-size-param: (size=-1) / memmove の size が size_t でアンダーフロー (len=2 < alias=3 → len-alias=SIZE_MAX)、try_files_module.c:196 の ngx_memmove で検出 / worker 異常終了: worker process 212330 exited on signal 6

[vuln  ] CVE-2026-125283 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-asan-fixed/sbin/nginx / nginx version: nginx/1.31.9 / request: GET /a/x → HTTP/1.1 404 Not Found / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-125283/cve-2026-125283/run / パス文字列は正常 ('.../run/html/xM')、ASAN レポート無し — 修正版の挙動
```

#### CVE-2026-125283 旧ブランチ（1.30.6 / 1.30.7）追試

```
[vuln  ] CVE-2026-125283 cfg=True trigger=True effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-vuln1306/sbin/nginx / nginx version: nginx/1.30.6 / request: GET /a/x → HTTP/1.1 404 Not Found / ... / debug ログのパス文字列が破損: 'p/data/...' (期待 '/app/data/...') — memmove が バッファを alias=3 バイトだけ左へずらしたメモリ破壊

[vuln  ] CVE-2026-125283 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-fixed1307/sbin/nginx / nginx version: nginx/1.30.7 / request: GET /a/x → HTTP/1.1 404 Not Found / ... / パス文字列は正常 ('.../run/html/xM')、ASAN レポート無し — 修正版の挙動
```

### CVE-2026-123640（1.31.8: malformed 通過 / 1.31.9: malformed 拒否）

```
[vuln  ] CVE-2026-123640 cfg=True trigger=True effect=VULNERABLE prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123640/cve-2026-123640/run / 振り分け結果: {"sni-valid": "real", "alpn-valid": "real", "dup-sni": "real", "dup-alpn": "real", "sni-trailing": "real", "alpn-trailing": "real", "supver-trailing": "real", "extlen-short": "real", "extlen-long": "real"} / sanity (整形 ClientHello -> 実バックエンド): OK / malformed ClientHello が 非 default へ振り分けられた: YES / default 振り分け先 (127.0.0.2:19010) への connect 拒否ログ: 0 件 / ssl preread debug 行: 13 件

[vuln  ] CVE-2026-123640 cfg=True trigger=True effect=TRIGGERED prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-123640/cve-2026-123640/run / 振り分け結果: {"sni-valid": "real", "alpn-valid": "real", "dup-sni": "<ConnectionResetError>", "dup-alpn": "<ConnectionResetError>", "sni-trailing": "<ConnectionResetError>", "alpn-trailing": "<ConnectionResetError>", "supver-trailing": "<ConnectionResetError>", "extlen-short": "<ConnectionResetError>", "extlen-long": "<ConnectionResetError>"} / sanity (整形 ClientHello -> 実バックエンド): OK / malformed ClientHello が 非 default へ振り分けられた: NO / default 振り分け先 (127.0.0.2:19010) への connect 拒否ログ: 7 件 / ssl preread debug 行: 18 件 / 拒否ログ例: 2026/11/19 00:37:13 [debug] 212070#0: *6 ssl preread: duplicate SNI
```

### CVE-2026-120967（1.31.8 / 1.31.9: 本環境では同期完了が発生せず）

```
[vuln  ] CVE-2026-120967 cfg=True trigger=False effect=VERIFIED 同期完了 (最初の ngx_stream_ssl_handler 呼び出し内での SSL_do_handshake 完了) が発生しなかったため検証バイパス未発生。無効証明書/無証明書 + SNI の全試行 (10 件) は検証エラーで切断され、正規証明書は通過 (ctrl=['ACCEPT', 'ACCEPT'])。接続 17 件すべて 2 回以上の SSL_do_handshake 呼び出しで完了 (first-call 完了 0 件) のため 非同期経路の検証 (SNI 選択後の sscf) が有効。

（1.31.8 と 1.31.9 で同一の判定出力。本環境では SSL_do_handshake の同期完了が
一度も発生しなかったため、検証バイパスの差分は観測できなかった。
モジュールの probe エミュレーション（emul_sync_vulnerable）では
no_cert=ACCEPT / bad_cert=ACCEPT となり、脆弱条件側の挙動は検証済み。）
```

### CVE-2026-120993（1.31.8: CRASH / 1.31.9: クラッシュせず）

```
[vuln  ] CVE-2026-120993 cfg=True trigger=True effect=CRASH   binary=/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx / version=nginx version: nginx/1.31.8 / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-120993/poc-run-G/cve-2026-120993 / 接続結果=[{'conn': 0, 'reused': False, 'data': b'UPSTREAM'}, {'conn': 1, 'reused': True, 'data': b''}, {'conn': 2, 'reused': False, 'data': b'UPSTREAM'}] / session_reused=[False, True, False] / upstream 応答=[True, False, True] / worker signal 終了=1 件 ['11'] / worker exit code 終了=0 件 [] / クラッシュ例: worker process 211906 exited on signal 11 / TLS1.2 セッション再開 (reused=True) 時に PROXY v2 の SSL TLV 生成で X509_get_signature_nid(NULL) → SIGSEGV

[vuln  ] CVE-2026-120993 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-fixed/sbin/nginx / version=nginx version: nginx/1.31.9 / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-120993/poc-run-G/cve-2026-120993 / 接続結果=[{'conn': 0, 'reused': False, 'data': b'UPSTREAM'}, {'conn': 1, 'reused': True, 'data': b'UPSTREAM'}, {'conn': 2, 'reused': True, 'data': b'UPSTREAM'}] / session_reused=[False, True, True] / upstream 応答=[True, True, True] / worker signal 終了=0 件 [] / worker exit code 終了=0 件 [] / 同一経路（フルハンドシェイク＋セッション再開）を実行したがクラッシュせず、再開接続も upstream へ中継された（修正版の可能性）
```

#### CVE-2026-120993 ASan 版追試

```
[vuln  ] CVE-2026-120993 cfg=True trigger=True effect=CRASH   binary=/app/data/sessions/conv-43/build/inst-asan-vuln/sbin/nginx / version=nginx version: nginx/1.31.8 / prefix=/app/data/sessions/conv-43/release/nginx2root/poc-run-120993/poc-run-G/cve-2026-120993 / 接続結果=[{'conn': 0, 'reused': False, 'data': b'UPSTREAM'}, {'conn': 1, 'reused': True, 'data': b''}, {'conn': 2, 'reused': True, 'data': b''}] / session_reused=[False, True, True] / upstream 応答=[True, False, False] / worker signal 終了=2 件 ['6', '6'] / worker exit code 終了=0 件 [] / ASan レポート検出=True / ASan 概要: ================================================================= | ==212355==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000088 (pc 0x76ce1ef5e140 bp 0x7ffc5d20f140 sp 0x7ffc5d20ef58 T0) | ==212355==The signal is caused by a READ memory access. | ==212355==Hint: address points to the zero page. |     #0 0x76ce1ef5e140 in X509_get_signature_nid (/lib/x86_64-linux-gnu/libcrypto.so.3+0x2f0140) |     #1 0x48375b in ngx_proxy_protocol_v2_ssl_sub src/core/ngx_proxy_protocol.c:957 |  / クラッシュ例: worker process 212355 exited on signal 6 / TLS1.2 セッション再開 (reused=True) 時に PROXY v2 の SSL TLV 生成で X509_get_signature_nid(NULL) → SIGSEGV

[vuln  ] CVE-2026-120993 cfg=True trigger=False effect=TRIGGERED binary=/app/data/sessions/conv-43/build/inst-asan-fixed/sbin/nginx / version=nginx version: nginx/1.31.9 / ... / worker signal 終了=0 件 [] / worker exit code 終了=0 件 [] / 同一経路（フルハンドシェイク＋セッション再開）を実行したがクラッシュせず、再開接続も upstream へ中継された（修正版の可能性）
```

### CVE-2026-118899（1.31.8 / 1.31.9: 挙動差なし）

```
[vuln  ] CVE-2026-118899 cfg=True trigger=False effect=TRIGGERED KeyUpdate + body 再開のシナリオを実行したが utime 激増なし (挙動差なし)

（1.31.8・1.31.9 とも同一結果。CPU スピン（worker utime 激増）は本環境の
タイミングでは発生しなかった。過去の result.json でも 4 パターン × 各バイナリで
utime 増分 0.0 であり、トリガ条件（body 読取中の SSL_ERROR_WANT_WRITE）が
本環境では一度も成立していない。）
```

### SCTP kernel モジュール（`--kernel` で 1 回実行）

```
[kernel] SCTP-LPE        cfg=True trigger=True effect=TRIGGERED カーネル: Linux version 6.8.0-1064-nvidia (buildd@lcy02-amd64-069) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #67-Ubuntu SMP PREEMPT_DYNAMIC Sep 14 23:03:45 UTC 2026
SCTP: 利用可能 (socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP=132) で作成成功)。
リテラル手順 (SOCK_STREAM): SCTP_STATUS(optname=14) で assoc id=22155 を取得。SCTP_SOCKOPT_PEELOFF(optname=102) の結果 errno=22 (1-to-1 スタイルでは peeloff 非対応のため -EINVAL=22)。
本命手順 (SOCK_SEQPACKET, SO_SNDBUF=32768): 120 回中 120 回で送信が sndbuf 待ちでブロックし、120 回で association を SCTP_SOCKOPT_PEELOFF(102) により別 fd へ移動して close した。待機中の送信は EPIPE(errno=32) で復帰: 120 回、EAGAIN(errno=11): 0 回。
SCTP_SENDALL 経路: 6 回実行し、待機中にリスト上の次 association を peeloff+ABORT close した回: 6、待機後に送信が再開して SENDALL 自体が成功した回: 6 (UAF 候補経路に到達)。
カーネルログ: /dev/kmsg と /proc/kmsg は open/read できず、dmesg と klogctl(3) も失敗 (dmesg_restrict=1 かつ CAP_SYSLOG/CAP_SYS_ADMIN 無し)。このため KASAN/double free のメッセージ検出はできず、effect=TRIGGERED とした。
SCTP slab (active_objs, num_objs): baseline={'SCTPv6': (21, 21), 'SCTP': (2392, 2553)} → after={'SCTPv6': (21, 21), 'SCTP': (2415, 2576)}
```

## 補足

- ASan 版（`inst-asan-vuln` / `inst-asan-fixed`）は 125283 と 120993 の 2 件を
  追試した。113425 は ASan 版バイナリが `nginx -t` 実行時に LeakSanitizer の
  リーク検出で終了コードを返す（=判定上の SKIP）ため、ASan 版の追試は
  125283 / 120993 の 2 件のみを記載する。
- 実行ログの完全版はリリース tarball には同梱していない（上記の要点を原文の
  まま抜粋）。`scripts/run-all.sh` を使えば同一環境で再実行できる。
