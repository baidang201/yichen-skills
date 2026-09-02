#!/usr/bin/env python3
"""Capture a WeCom 5.x raw database key from macOS attach or a signed copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import queue
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from wecom_common import (
    choose_dataset,
    dataset_id,
    discover_datasets,
    inspect_dataset,
    save_validated_key,
    validate_candidate,
    vault_root,
)


FRIDA_AGENT = r"""
'use strict';

const seen = new Set();

// WeCom 5.0.10 (arm64) wxsqlite3 page codec, verified by static analysis of the
// on-disk binary (2026-09): the per-page key-derivation entry sits at
// main_base + 0x280428.  Its prologue is sub sp,sp,#0x90; stp x24,x23,[sp,#0x50];
// stp x22,x21,[sp,#0x60]; stp x20,x19,[sp,#0x70].  At entry args[3] points to the
// 16-byte raw database key; the function then builds
//   raw_key(16) || page_number(LE32) || "sAlT"(4)
// on the stack and MD5s it (len 0x18) to derive the AES-128 page key, matching
// wecom_crypto.page_key.  The previous offsets (0x42f7a4c / 0x2885074 /
// 0x278870) came from an older build and landed on unrelated epilogue code,
// which is why Interceptor reported "unable to intercept".
const WXSQLITE_PAGE_DERIVE_OFFSET = 0x280428;
const WXSQLITE_PAGE_DERIVE_PROLOGUE = 'ff4302d1f85f05a9f65706a9f44f07a9';

// Unique instruction fingerprint inside the same derive function: the page-IV
// LCG immediate loads (40692/0x9ef4, 52774/0xce26, -3791/-0xecf, 2147483399/
// 0x7fffffe7 -- the exact constants implemented in wecom_crypto.page_iv).
// When a WeCom update shifts code around, this lets us re-locate the function
// at runtime instead of trusting a stale offset.  When execution reaches the
// match, the raw key copy still sits at [sp] in the derive frame.
const WXSQLITE_LCG_SIGNATURE = 'c9c49952aac499128cde9352cdd98112eee09f52eeffaf72';
const WXSQLITE_TEXT_OFFSET = 0x1b000;
const MAX_REPORTED_CANDIDATES = 8192;

function hex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => ('0' + b.toString(16)).slice(-2)).join('');
}

function isHexAscii(bytes) {
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    const ok = (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);
    if (!ok) return false;
  }
  return true;
}

function hexAsciiToBytes(bytes) {
  const text = Array.from(bytes).map(b => String.fromCharCode(b)).join('');
  const output = new Uint8Array(text.length / 2);
  for (let i = 0; i < output.length; i++) {
    output[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return output.buffer;
}

function report(pointer, length, source) {
  if (!pointer || pointer.isNull() || length <= 0 || length > 64) return;
  if (seen.size >= MAX_REPORTED_CANDIDATES) return;
  try {
    let bytes = pointer.readByteArray(length);
    if (length === 32) {
      const view = new Uint8Array(bytes);
      if (!isHexAscii(view)) return;
      bytes = hexAsciiToBytes(view);
      length = 16;
    }
    if (length !== 16) return;
    const value = hex(bytes);
    if (seen.has(value)) return;
    seen.add(value);
    send({type: 'candidate', source: source, key: value});
  } catch (_) {}
}

function mainModule() {
  return Process.enumerateModules().find(m => m.path.indexOf('/Contents/MacOS/企业微信') !== -1);
}

function readHexAt(pointer, length) {
  return Array.from(new Uint8Array(pointer.readByteArray(length))).map(b => ('0' + b.toString(16)).slice(-2)).join('');
}

function hookWxsqlitePageCrypt() {
  const main = mainModule();
  if (!main) {
    send({type: 'agent-error', description: 'wxsqlite3 hook: main module not found'});
    return false;
  }
  // Primary: 5.0.10 static offset, only trusted when the on-disk prologue still
  // matches, so a shifted build can never be hooked blindly (that is exactly
  // the failure mode that produced "unable to intercept function" before).
  if (main.size > WXSQLITE_PAGE_DERIVE_OFFSET) {
    const target = main.base.add(WXSQLITE_PAGE_DERIVE_OFFSET);
    try {
      const actual = readHexAt(target, 16);
      if (actual === WXSQLITE_PAGE_DERIVE_PROLOGUE) {
        Interceptor.attach(target, {
          onEnter(args) {
            // args[3] = pointer to the 16-byte raw database key.
            report(args[3], 16, 'wxsqlite3-page-raw-key');
          }
        });
        send({type: 'hook', name: 'wxsqlite3-page-raw-key'});
        return true;
      }
      send({type: 'agent-error', description: 'wxsqlite3 offset 0x' + WXSQLITE_PAGE_DERIVE_OFFSET.toString(16) + ' prologue mismatch (' + actual + '); falling back to signature scan'});
    } catch (error) {
      send({type: 'agent-error', description: 'wxsqlite3 offset read failed: ' + error + '; falling back to signature scan'});
    }
  }
  // Fallback: locate the derive function by its unique LCG fingerprint inside
  // __text, then hook the match itself.  At that point the frame still holds
  // the raw key at [sp] (copied there just before the MD5 call over
  // key||pageno||"sAlT"), and sp is stable for the rest of the frame.
  try {
    const scanSize = Math.min(0x921c774, main.size - WXSQLITE_TEXT_OFFSET);
    if (scanSize <= WXSQLITE_LCG_SIGNATURE.length / 2) {
      send({type: 'agent-error', description: 'wxsqlite3 signature scan: __text range unavailable'});
      return false;
    }
    const matches = Memory.scanSync(main.base.add(WXSQLITE_TEXT_OFFSET), scanSize, WXSQLITE_LCG_SIGNATURE);
    if (!matches.length) {
      send({type: 'agent-error', description: 'wxsqlite3 page derive not found (signature miss); WeCom build changed, re-derive offsets'});
      return false;
    }
    Interceptor.attach(matches[0].address, {
      onEnter(_args) {
        try {
          report(this.context.sp, 16, 'wxsqlite3-page-raw-key-scan');
        } catch (_) {}
      }
    });
    send({type: 'hook', name: 'wxsqlite3-page-raw-key (sigscan)'});
    return true;
  } catch (error) {
    send({type: 'agent-error', description: 'wxsqlite3 signature scan failed: ' + error});
    return false;
  }
}

function findExport(name) {
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
  } catch (_) {}
  try {
    if (Module.findExportByName) return Module.findExportByName(null, name);
  } catch (_) {}
  return null;
}

function hook(name, callbacks) {
  const address = findExport(name);
  if (!address) return false;
  Interceptor.attach(address, callbacks);
  send({type: 'hook', name: name});
  return true;
}

// Note: the old DbKeyManager::UpdateKey / GetAllLocalEncryptKey fixed-offset
// hooks were removed.  Their offsets (0x42f7a4c / 0x2885074) pointed at
// unrelated code in 5.0.10 (function epilogues), so Interceptor failed with
// "unable to intercept function".  The wxsqlite3 page-derive hook below is a
// superset: it captures the same raw key on every page turn of any encrypted
// database, without needing those higher-level call sites.

hook('CC_MD5', {
  onEnter(args) {
    const length = args[1].toUInt32();
    if (length !== 24) return;
    try {
      const input = new Uint8Array(args[0].readByteArray(24));
      if (input[20] === 0x73 && input[21] === 0x41 && input[22] === 0x6c && input[23] === 0x54) {
        report(args[0], 16, 'CC_MD5-key-page-sAlT');
      }
    } catch (_) {}
  }
});

hook('CCCryptorCreate', {
  onEnter(args) {
    const algorithm = args[1].toInt32();
    const keyLength = args[4].toUInt32();
    if (algorithm === 0) report(args[3], keyLength, 'CCCryptorCreate-AES128');
  }
});

hook('CCCryptorCreateWithMode', {
  onEnter(args) {
    const algorithm = args[2].toInt32();
    const keyLength = args[6].toUInt32();
    if (algorithm === 0) report(args[5], keyLength, 'CCCryptorCreateWithMode-AES128');
  }
});

hook('CCCrypt', {
  onEnter(args) {
    const algorithm = args[1].toInt32();
    const keyLength = args[4].toUInt32();
    if (algorithm === 0) report(args[3], keyLength, 'CCCrypt-AES128');
  }
});

hook('sqlite3_key', {
  onEnter(args) {
    report(args[1], args[2].toInt32(), 'sqlite3_key');
  }
});

hook('sqlite3_key_v2', {
  onEnter(args) {
    report(args[2], args[3].toInt32(), 'sqlite3_key_v2');
  }
});

hook('sqlite3_rekey', {
  onEnter(args) {
    report(args[1], args[2].toInt32(), 'sqlite3_rekey');
  }
});

hook('sqlite3_rekey_v2', {
  onEnter(args) {
    report(args[2], args[3].toInt32(), 'sqlite3_rekey_v2');
  }
});

hookWxsqlitePageCrypt();

send({type: 'ready'});
"""

ORIGINAL_WECOM_APP = Path("/Applications/企业微信.app")


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def find_pid() -> int:
    patterns = (
        "/Applications/企业微信.app/Contents/MacOS/企业微信",
        "企业微信",
    )
    for pattern in patterns:
        result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            if line.strip().isdigit():
                return int(line.strip())
    raise SystemExit("企业微信当前未运行；本脚本不会自动启动客户端")


def choose_capture_dataset(data_dir: str | None):
    if data_dir:
        return choose_dataset(data_dir)
    datasets = discover_datasets()
    if not datasets:
        return choose_dataset(None)
    if len(datasets) == 1:
        return datasets[0]
    return sorted(
        datasets,
        key=lambda path: (inspect_dataset(path)["wal_count"], inspect_dataset(path)["database_count"]),
    )[-1]


def default_signed_copy_path() -> Path:
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return vault_root() / "apps" / f"WeComSigned-{stamp}.app"


def default_candidate_dump_path() -> Path:
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    return vault_root() / "private" / f"capture-candidates-{stamp}.json"


def write_candidate_dump(records: list[dict], dataset: Path, destination: Path | None) -> Path:
    path = destination or default_candidate_dump_path()
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing candidate dump: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = {
        "version": 1,
        "captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset_id": dataset_id(dataset),
        "candidate_count": len(records),
        "candidates": records,
    }
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)
    return path


def prepare_signed_copy(source_app: Path, copy_path: Path, reuse: bool) -> Path:
    if not source_app.exists():
        raise SystemExit(f"找不到企业微信 App: {source_app}")
    if copy_path.exists():
        if not reuse:
            raise SystemExit(f"签名副本已存在，拒绝覆盖: {copy_path}")
        print(f"复用已有企业微信签名副本: {copy_path}")
    else:
        print(f"复制企业微信副本: {source_app} -> {copy_path}")
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_app, copy_path, symlinks=True)
        print("对企业微信副本做 ad-hoc 重签，并保留原 App entitlements。")
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--deep",
                "--sign",
                "-",
                "--preserve-metadata=entitlements",
                str(copy_path),
            ],
            check=True,
        )
    executable = copy_path / "Contents/MacOS/企业微信"
    if not executable.exists():
        raise SystemExit(f"签名副本缺少可执行文件: {executable}")
    return executable


def list_only(data_dir: str | None) -> int:
    dataset = choose_capture_dataset(data_dir)
    summary = inspect_dataset(dataset)
    print(f"dataset_id: {summary['dataset_id']}")
    print(f"databases: {summary['database_count']}")
    print(f"formats: {summary['formats']}")
    print(f"wal_files: {summary['wal_count']}")
    print("未附加企业微信进程。")
    return 0


def _probe(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {type(exc).__name__}"
    text = (result.stdout or result.stderr).strip().replace("\n", " | ")
    return text or f"exit={result.returncode}"


def doctor(data_dir: str | None) -> int:
    dataset = choose_capture_dataset(data_dir)
    summary = inspect_dataset(dataset)
    try:
        import frida
        frida_version = getattr(frida, "__version__", "unknown")
    except ImportError:
        frida_version = "missing"
    checks = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "frida": frida_version,
        "dataset_id": summary["dataset_id"],
        "encrypted_databases": summary["formats"].get("wecom-wxsqlite3-aes128", 0),
        "devtools_security": _probe(["/usr/sbin/DevToolsSecurity", "-status"]),
        "sip": _probe(["/usr/bin/csrutil", "status"]),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    print("doctor 不附加任何进程，也不会修改系统安全设置。")
    if frida_version == "missing":
        return 2
    return 0


def capture(args: argparse.Namespace) -> int:
    if args.mode == "attach" and not args.confirm_attach:
        raise SystemExit("为防止误附加，capture 必须显式添加 --confirm-attach")
    if sys.platform != "darwin":
        raise SystemExit("Mac 密钥捕获仅支持 macOS")
    try:
        import frida
    except ImportError as exc:
        raise SystemExit("缺少 frida；请在隔离环境中安装 frida 后重试") from exc

    dataset = choose_capture_dataset(args.data_dir)
    messages: queue.Queue[dict] = queue.Queue()
    hooks: set[str] = set()
    validated_key: bytes | None = None
    validated_dbs: list[str] = []
    candidate_records: list[dict] = []

    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            if isinstance(payload, dict):
                messages.put(payload)
        elif message.get("type") == "error":
            messages.put({"type": "agent-error", "description": message.get("description", "unknown")})

    def on_detached(reason, crash):
        payload = {"type": "detached", "reason": str(reason)}
        if crash is not None:
            payload["crash"] = str(crash)
        messages.put(payload)

    def on_output(_pid, _fd, _data):
        # Target stdout/stderr can contain sensitive WeCom runtime logs.  Drain
        # and discard it so the spawned app cannot block on a full pipe.
        return None

    device = frida.get_local_device()
    output_handler_registered = False
    spawned_pid: int | None = None
    if args.mode == "attach":
        pid = args.pid or find_pid()
        print(f"只读附加企业微信进程 PID={pid}，最长等待 {args.duration} 秒。")
        print("密钥在数据库页面读写时出现；如长时间无候选，请在企微里切换会话或刷新消息列表。")
    else:
        if not args.confirm_signed_copy:
            raise SystemExit("spawn-signed-copy 必须显式添加 --confirm-signed-copy")
        copy_path = Path(args.wecom_copy).expanduser() if args.wecom_copy else default_signed_copy_path()
        source_app = Path(args.source_app).expanduser()
        executable = prepare_signed_copy(source_app, copy_path, args.reuse_signed_copy)
        print(f"通过 Frida 启动企业微信签名副本，最长等待 {args.duration} 秒。")
        print("如果副本要求登录，请你手动登录；脚本不会点击或发送任何消息。")
        try:
            device.on("output", on_output)
            output_handler_registered = True
        except Exception:
            output_handler_registered = False
        try:
            pid = device.spawn([str(executable)], stdio="pipe")
        except TypeError:
            pid = device.spawn([str(executable)])
        spawned_pid = pid
        print(f"签名副本 PID={pid}")
    session = None
    script = None
    try:
        session = device.attach(pid)
        session.on("detached", on_detached)
        script = session.create_script(FRIDA_AGENT)
        script.on("message", on_message)
        script.load()
        if spawned_pid is not None:
            device.resume(spawned_pid)
    except frida.PermissionDeniedError as exc:
        if session is not None:
            session.detach()
        raise SystemExit(
            "macOS 拒绝 task_for_pid，未附加企业微信。可改用 --mode spawn-signed-copy 捕获企业微信签名副本。"
        ) from exc
    deadline = time.monotonic() + args.duration
    target_exited = False
    try:
        while time.monotonic() < deadline and validated_key is None:
            if spawned_pid is not None and not process_exists(spawned_pid):
                target_exited = True
                print("签名副本进程已经退出；停止等待。", file=sys.stderr)
                break
            try:
                payload = messages.get(timeout=min(0.5, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            kind = payload.get("type")
            if kind == "hook":
                hooks.add(str(payload.get("name")))
                if args.debug_candidates:
                    print(f"hooked: {payload.get('name')}", file=sys.stderr)
            elif kind == "hook-event":
                if args.debug_candidates:
                    extra = ""
                    if "count" in payload:
                        extra = f" count={payload.get('count')}"
                    print(f"hook-event: {payload.get('name')}{extra}", file=sys.stderr)
            elif kind == "candidate":
                try:
                    candidate = bytes.fromhex(str(payload.get("key", "")))
                except ValueError:
                    continue
                validated = validate_candidate(candidate, dataset)
                if args.debug_candidates:
                    digest = hashlib.sha256(candidate).hexdigest()[:12]
                    print(
                        f"candidate source={payload.get('source')} sha256_12={digest} validated_db_count={len(validated)}",
                        file=sys.stderr,
                    )
                if args.save_candidates:
                    candidate_records.append(
                        {
                            "source": str(payload.get("source")),
                            "sha256_12": hashlib.sha256(candidate).hexdigest()[:12],
                            "key_hex": candidate.hex(),
                            "validated_databases": validated,
                        }
                    )
                if validated:
                    validated_key = candidate
                    validated_dbs = validated
            elif kind == "agent-error":
                print(f"Frida agent error: {payload.get('description')}", file=sys.stderr)
            elif kind == "detached":
                target_exited = True
                reason = payload.get("reason")
                crash = payload.get("crash")
                if crash:
                    print(f"Frida session detached: {reason}; crash={crash}", file=sys.stderr)
                else:
                    print(f"Frida session detached: {reason}", file=sys.stderr)
                break
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if output_handler_registered:
            try:
                device.off("output", on_output)
            except Exception:
                pass

    if not hooks:
        if args.save_candidates and candidate_records:
            saved_candidates = write_candidate_dump(
                candidate_records,
                dataset,
                Path(args.candidate_output).expanduser() if args.candidate_output else None,
            )
            print(f"已保存候选诊断文件：{saved_candidates}")
        if target_exited:
            print("签名副本在 Frida agent 就绪前退出；未保存任何 key。", file=sys.stderr)
            return 4
        print("未找到可挂接的 CommonCrypto 入口；企业微信可能使用了静态加密实现。", file=sys.stderr)
        return 2
    if validated_key is None:
        if args.save_candidates and candidate_records:
            saved_candidates = write_candidate_dump(
                candidate_records,
                dataset,
                Path(args.candidate_output).expanduser() if args.candidate_output else None,
            )
            print(f"已保存候选诊断文件：{saved_candidates}")
        if target_exited:
            print("签名副本退出前没有出现能通过数据库第一页校验的密钥。未保存任何 key。", file=sys.stderr)
            return 4
        print("捕获期间没有出现能通过数据库第一页校验的密钥。未保存任何 key。", file=sys.stderr)
        return 3
    output = Path(args.output).expanduser() if args.output else None
    saved = save_validated_key(validated_key, dataset, validated_dbs, output)
    print(f"已保存经 {len(validated_dbs)} 个数据库验证的 key：{saved}")
    print("终端未显示密钥内容；文件权限为 0600。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="WeCom macOS database-key helper")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list", help="只发现数据库，不附加进程")
    list_parser.add_argument("--data-dir")
    doctor_parser = sub.add_parser("doctor", help="检查依赖和 macOS 安全状态，不附加进程")
    doctor_parser.add_argument("--data-dir")
    capture_parser = sub.add_parser("capture", help="附加已运行企业微信，或启动重签副本捕获候选 key")
    capture_parser.add_argument("--mode", choices=["attach", "spawn-signed-copy"], default="attach")
    capture_parser.add_argument("--data-dir")
    capture_parser.add_argument("--pid", type=int)
    capture_parser.add_argument("--duration", type=int, default=60)
    capture_parser.add_argument("--output", help="新密钥文件路径；已存在时拒绝覆盖")
    capture_parser.add_argument("--confirm-attach", action="store_true")
    capture_parser.add_argument("--confirm-signed-copy", action="store_true")
    capture_parser.add_argument("--source-app", default=str(ORIGINAL_WECOM_APP))
    capture_parser.add_argument("--wecom-copy", help="签名副本 .app 目录；默认写入私密 vault/apps/ 时间戳目录")
    capture_parser.add_argument("--reuse-signed-copy", action="store_true")
    capture_parser.add_argument("--debug-candidates", action="store_true", help="打印候选来源和短 hash，不打印 raw key")
    capture_parser.add_argument("--save-candidates", action="store_true", help="把 raw 候选写入私密 vault 诊断文件，不在终端显示")
    capture_parser.add_argument("--candidate-output", help="候选诊断文件路径；已存在时拒绝覆盖")
    args = parser.parse_args()
    if args.command == "list":
        return list_only(args.data_dir)
    if args.command == "doctor":
        return doctor(args.data_dir)
    return capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
