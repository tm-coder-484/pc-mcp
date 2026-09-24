"""The MCP server: tool definitions, audit logging and the optional per-action confirmation prompt."""

from __future__ import annotations

import functools
import heapq
import io
import json
import os
import socket
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import psutil
from mcp.server.mcpserver import Image, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from pc_mcp import __version__, diagnostics
from pc_mcp import shell as sh

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
CHANGES_SYSTEM = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

PROTECTED_NAMES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "launchd",
    "kernel_task",
    "windowserver",
    "loginwindow",
    "systemd",
    "init",
    "cloudflared",
    "cloudflared.exe",
}


@dataclass
class Config:
    mode: Literal["full", "read-only"] = "full"
    confirm: bool = False
    home: Path = field(default_factory=lambda: Path.home() / ".pc-mcp")
    max_sync_timeout: int = 90
    quiet: bool = False


# --------------------------------------------------------------------------------------------------
# Console output, audit log and confirmations
# --------------------------------------------------------------------------------------------------


class Console:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        cfg.home.mkdir(parents=True, exist_ok=True)
        self.audit_path = cfg.home / "audit.log"

    def event(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            if not self.cfg.quiet:
                print(f"  [{stamp}] {text}", flush=True)
            try:
                with open(self.audit_path, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat(timespec='seconds')} {text}\n")
            except OSError:
                pass

    def confirm(self, action: str, timeout: float = 120) -> bool:
        """Ask the person sitting at this PC to approve an action. Denies on timeout."""
        with self._lock:
            print("\n" + "=" * 70, flush=True)
            print("  Claude wants to:", flush=True)
            for line in action.splitlines()[:30]:
                print(f"    {line}", flush=True)
            print(
                f"  Allow? Type y + Enter to allow, anything else denies (auto-deny in {int(timeout)}s): ",
                end="",
                flush=True,
            )
            answer = _input_with_timeout(timeout)
            print("=" * 70, flush=True)
        return answer.strip().lower() in ("y", "yes")


def _input_with_timeout(timeout: float) -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return ""
    if sys.platform == "win32":
        import msvcrt

        chars: list[str] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getwche()
                if ch in ("\r", "\n"):
                    print(flush=True)
                    return "".join(chars)
                chars.append(ch)
            else:
                time.sleep(0.05)
        print(flush=True)
        return ""
    import select

    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if not ready:
        print(flush=True)
        return ""
    return sys.stdin.readline()


def _brief(kwargs: dict[str, Any], limit: int = 160) -> str:
    parts = []
    for k, v in kwargs.items():
        if v is None:
            continue
        text = v if isinstance(v, str) else json.dumps(v, default=str)
        if k == "content":
            text = f"<{len(v)} chars>"
        parts.append(f"{k}={text}")
    s = " ".join(parts).replace("\n", " ⏎ ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


# --------------------------------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------------------------------


def build_server(cfg: Config | None = None) -> tuple[MCPServer, sh.JobManager, Console]:
    cfg = cfg or Config()
    console = Console(cfg)
    jobs = sh.JobManager(cfg.home / "jobs")
    host = socket.gethostname()
    os_name = diagnostics.machine_info()["os"]
    default_shell = sh.default_shell()

    instructions = f"""You are connected to a real personal computer: {host} running {os_name}, user {_whoami()}.
Tool access mode: {cfg.mode}{" (every command/change must be approved by the person at the PC)" if cfg.confirm else ""}.
- run_command uses {default_shell} by default{" (Windows PowerShell 5.1; use PowerShell syntax)" if sys.platform == "win32" else ""}.
  Commands time out after {cfg.max_sync_timeout}s max; for longer work pass background=true and poll check_job.
- For "my PC is slow" style problems, start with diagnose_performance, then drill in with list_processes,
  find_space_hogs and run_command.
- This is someone's own machine: prefer read-only investigation, explain what you intend to change, and get the
  user's go-ahead before deleting files, killing important programs, uninstalling software or changing settings.
"""
    mcp = MCPServer(
        "pc-mcp",
        title=f"PC: {host}",
        version=__version__,
        instructions=instructions,
        log_level="WARNING",
    )

    def register(fn: Callable, annotations: ToolAnnotations, changes_system: bool = False, confirm_text=None) -> None:
        name = fn.__name__

        @functools.wraps(fn)
        def wrapper(**kwargs):
            console.event(f"→ {name} {_brief(kwargs)}")
            if changes_system and cfg.confirm:
                text = confirm_text(kwargs) if confirm_text else f"{name} {_brief(kwargs, 2000)}"
                if not console.confirm(text):
                    console.event(f"✗ {name} denied by user")
                    raise ToolError("The person at the PC denied this action.")
            t0 = time.monotonic()
            try:
                result = fn(**kwargs)
            except ToolError as e:
                console.event(f"✗ {name} failed: {e}")
                raise
            except Exception as e:  # surface the real reason to the model
                console.event(f"✗ {name} failed: {type(e).__name__}: {e}")
                raise ToolError(f"{type(e).__name__}: {e}") from e
            console.event(f"✓ {name} ({time.monotonic() - t0:.1f}s)")
            return result

        mcp.add_tool(wrapper, name=name, annotations=annotations)

    # ---- information --------------------------------------------------------------------------------

    def system_info() -> dict:
        """Overview of this PC: OS, hardware, CPU/RAM, uptime, disks, battery, current user and default shell.
        Cheap and instant - call it first to learn what kind of machine you are talking to."""
        info = diagnostics.machine_info()
        info["memory"] = diagnostics.memory_state()
        info["volumes"] = diagnostics.volumes()
        info["battery"] = diagnostics.battery()
        info["default_shell"] = default_shell
        info["home_directory"] = str(Path.home())
        info["pc_mcp"] = {"version": __version__, "mode": cfg.mode, "confirm_each_action": cfg.confirm}
        return info

    def diagnose_performance(sample_seconds: int = 5, include_os_checks: bool = True) -> dict:
        """Full "why is my PC slow?" diagnosis. Samples CPU, RAM, disk and network activity for `sample_seconds`
        (per process too), then checks OS-specific evidence: power plan / CPU throttling, disk type and health,
        free space, page-file/commit pressure, startup programs, uptime and pending reboots, event-log disk and
        hardware errors, app crashes, antivirus conflicts, temperatures.
        Returns `summary` and ranked `findings` (critical > warning > info, each with a suggested fix) followed by
        the raw measurements. Takes roughly sample_seconds + 5-20 s. Run it while the slowness is happening."""
        return diagnostics.diagnose(sample_seconds=max(1, min(sample_seconds, 30)), include_os_checks=include_os_checks)

    def list_processes(
        sort_by: Literal["cpu", "memory", "disk", "name", "pid"] = "cpu",
        limit: int = 25,
        name_contains: str | None = None,
        sample_seconds: float = 1.0,
    ) -> dict:
        """Running processes with CPU % (of the whole machine, measured over `sample_seconds`), memory (MB),
        disk I/O (MB/s, where the OS supports it), user and command line. Filter with `name_contains`."""
        data = diagnostics.sample(max(1.0, min(sample_seconds, 10.0)))
        rows = data["processes"]
        if name_contains:
            rows = [r for r in rows if name_contains.lower() in r["name"].lower()]
        key = {
            "cpu": lambda r: -r["cpu_percent_of_total"],
            "memory": lambda r: -r["memory_mb"],
            "disk": lambda r: -(r.get("disk_read_mb_s", 0) + r.get("disk_write_mb_s", 0)),
            "name": lambda r: r["name"].lower(),
            "pid": lambda r: r["pid"],
        }[sort_by]
        rows = sorted(rows, key=key)[: max(1, min(limit, 500))]
        for r in rows:
            try:
                p = psutil.Process(r["pid"])
                r["user"] = p.username()
                r["started"] = datetime.fromtimestamp(p.create_time()).isoformat(timespec="seconds")
                r["command_line"] = " ".join(p.cmdline())[:300]
            except (psutil.Error, OSError):
                pass
        return {
            "cpu_percent_total": data["cpu_percent"],
            "memory_used_percent": psutil.virtual_memory().percent,
            "process_count": data["process_count"],
            "processes": rows,
        }

    def find_space_hogs(path: str | None = None, top: int = 20, max_seconds: int = 40) -> dict:
        """Find what is using disk space under `path` (default: the system drive on Windows, your home folder
        elsewhere). Returns the sizes of the immediate sub-folders and the largest individual files. Scans for at
        most `max_seconds`; the result says if it was cut short."""
        root = Path(os.path.expanduser(path)) if path else _default_scan_root()
        if not root.is_dir():
            raise ToolError(f"not a directory: {root}")
        return _scan_sizes(root, top=max(1, min(top, 100)), max_seconds=max(5, min(max_seconds, 80)))

    def list_directory(path: str = "~", show_hidden: bool = False, limit: int = 300) -> dict:
        """List a folder: name, type, size and modification time of each entry (folders first)."""
        root = Path(os.path.expanduser(path))
        entries = []
        with os.scandir(root) as it:
            for e in it:
                if not show_hidden and (e.name.startswith(".") or _is_hidden_windows(e)):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                    is_dir = e.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                entries.append(
                    {
                        "name": e.name,
                        "type": "dir" if is_dir else ("link" if e.is_symlink() else "file"),
                        "size": None if is_dir else st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                    }
                )
        entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
        total = len(entries)
        return {
            "path": str(root.resolve()),
            "total_entries": total,
            "entries": entries[: max(1, limit)],
            "truncated": total > limit,
        }

    def read_file(path: str, offset: int = 0, max_chars: int = 60_000) -> dict:
        """Read a text file (logs, configs, scripts). Use `offset` (characters) to page through big files."""
        p = Path(os.path.expanduser(path))
        with open(p, "rb") as f:
            head = f.read(8192)
        if b"\x00" in head and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise ToolError("this looks like a binary file; use run_command to inspect it")
        encoding = "utf-16" if head.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
        text = p.read_text(encoding=encoding, errors="replace")
        chunk = text[offset : offset + max(1, min(max_chars, 500_000))]
        return {
            "path": str(p.resolve()),
            "total_chars": len(text),
            "offset": offset,
            "returned_chars": len(chunk),
            "more": offset + len(chunk) < len(text),
            "content": chunk,
        }

    for fn in (system_info, diagnose_performance, list_processes, find_space_hogs, list_directory, read_file):
        register(fn, READ_ONLY)

    @mcp.prompt()
    def diagnose_slow_pc() -> str:
        """Investigate why this PC is slow and propose fixes."""
        return (
            "My PC feels slow. Run diagnose_performance, explain the findings in plain language ordered by impact, "
            "drill into anything unclear with list_processes / find_space_hogs / run_command, and propose concrete "
            "fixes. Ask me before changing anything."
        )

    if cfg.mode == "read-only":
        return mcp, jobs, console

    # ---- actions --------------------------------------------------------------------------------------

    def run_command(
        command: str,
        shell: Literal["auto", "powershell", "pwsh", "cmd", "bash", "zsh", "sh"] = "auto",
        cwd: str | None = None,
        timeout_seconds: int = 60,
        background: bool = False,
    ) -> dict:
        """Run a shell command on this PC and return exit code, stdout and stderr.
        `shell`: auto = PowerShell on Windows, bash (or sh) on macOS/Linux; cmd is Windows-only.
        Commands get no stdin, so interactive prompts fail fast - pass non-interactive flags (e.g. -y, -Force).
        `timeout_seconds` is capped by the server (see instructions). For anything longer (scans, installs,
        benchmarks, sfc /scannow) set background=true: you get a job_id to poll with check_job."""
        if background:
            job = jobs.start(command, shell, cwd)
            return {"job_id": job.id, "status": "running", "hint": "poll with check_job(job_id, wait_seconds=...)"}
        timeout = max(1, min(timeout_seconds, cfg.max_sync_timeout))
        return sh.run(command, shell, cwd, timeout=timeout)

    def check_job(job_id: str, wait_seconds: int = 0, tail_chars: int = 8000) -> dict:
        """Status and latest output of a background job. `wait_seconds` (max 60) blocks until the job ends or
        the wait runs out - handy to avoid rapid polling."""
        job = jobs.get(job_id)
        jobs.wait(job, max(0, min(wait_seconds, 60)))
        return jobs.describe(job, tail_chars=max(200, min(tail_chars, 200_000)))

    def stop_job(job_id: str) -> dict:
        """Stop a background job (and any processes it started)."""
        job = jobs.get(job_id)
        jobs.stop(job)
        return jobs.describe(job, tail_chars=2000)

    def list_jobs() -> list[dict]:
        """All background jobs started in this session with their status."""
        return [
            {
                "job_id": j.id,
                "status": j.status(),
                "exit_code": j.proc.returncode,
                "command": j.command[:200],
                "started": datetime.fromtimestamp(j.started_at).isoformat(timespec="seconds"),
            }
            for j in jobs.all()
        ]

    def kill_process(pid: int, force: bool = False, include_children: bool = False) -> dict:
        """End a process by PID (get PIDs from list_processes). `force` kills immediately instead of asking it to
        close. Core OS processes are refused."""
        if pid <= 4 or pid in (os.getpid(), os.getppid()):
            raise ToolError("refusing to kill a core system process or pc-mcp itself")
        p = psutil.Process(pid)
        name = p.name()
        if name.lower() in PROTECTED_NAMES:
            raise ToolError(f"refusing to kill {name}: it is a core OS component")
        targets = (p.children(recursive=True) if include_children else []) + [p]
        for t in targets:
            try:
                t.kill() if force else t.terminate()
            except psutil.NoSuchProcess:
                pass
        gone, alive = psutil.wait_procs(targets, timeout=5)
        return {
            "pid": pid,
            "name": name,
            "ended": [t.pid for t in gone],
            "still_running": [t.pid for t in alive],
            "hint": "retry with force=true" if alive and not force else "",
        }

    def write_file(path: str, content: str, append: bool = False, create_dirs: bool = True) -> dict:
        """Create, overwrite or append to a text file (UTF-8)."""
        p = Path(os.path.expanduser(path))
        if create_dirs:
            p.parent.mkdir(parents=True, exist_ok=True)
        existed = p.exists()
        with open(p, "a" if append else "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return {
            "path": str(p.resolve()),
            "bytes_written": len(content.encode()),
            "existed_before": existed,
            "appended": append,
        }

    def take_screenshot(max_width: int = 1600) -> Image:
        """Capture the screen(s) of this PC as a JPEG image, scaled down to at most `max_width` pixels wide."""
        from PIL import ImageGrab

        try:
            img = ImageGrab.grab(all_screens=True) if sys.platform == "win32" else ImageGrab.grab()
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"screenshot failed ({e}); on macOS allow Screen Recording for your terminal app") from e
        img = img.convert("RGB")
        if img.width > max_width:
            img = img.resize((max_width, round(img.height * max_width / img.width)))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=70)
        return Image(data=buf.getvalue(), format="jpeg")

    register(
        run_command,
        CHANGES_SYSTEM,
        changes_system=True,
        confirm_text=lambda a: (
            f"run ({a.get('shell', 'auto')}{', background' if a.get('background') else ''}):\n{a['command']}"
        ),
    )
    register(check_job, READ_ONLY)
    register(stop_job, CHANGES_SYSTEM)
    register(list_jobs, READ_ONLY)
    register(
        kill_process,
        CHANGES_SYSTEM,
        changes_system=True,
        confirm_text=lambda a: f"end process PID {a['pid']} ({_pname(a['pid'])})",
    )
    register(
        write_file,
        CHANGES_SYSTEM,
        changes_system=True,
        confirm_text=lambda a: (
            f"{'append to' if a.get('append') else 'write'} file {a['path']} ({len(a['content'])} chars)"
        ),
    )
    register(take_screenshot, READ_ONLY, changes_system=True, confirm_text=lambda a: "take a screenshot of your screen")
    return mcp, jobs, console


def _whoami() -> str:
    try:
        return psutil.Process().username()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "?"


def _pname(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return "unknown"


def _is_hidden_windows(entry: os.DirEntry) -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(entry.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    except (OSError, AttributeError):
        return False


def _default_scan_root() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("SystemDrive", "C:") + "\\")
    return Path.home()


_SKIP_ATTRS = 0x400 | 0x1000 | 0x400000  # reparse point, offline, recall-on-data-access (cloud placeholders)


def _scan_sizes(root: Path, top: int, max_seconds: int) -> dict:
    deadline = time.monotonic() + max_seconds
    child_sizes: dict[str, int] = {}
    biggest: list[tuple[int, str]] = []
    files = errors = 0
    partial = False
    root_files_size = 0
    try:
        top_entries = list(os.scandir(root))
    except OSError as e:
        raise ToolError(f"cannot read {root}: {e}") from e
    for top_entry in top_entries:
        if time.monotonic() > deadline:
            partial = True
            break
        try:
            if _skip(top_entry):
                continue
            if not top_entry.is_dir(follow_symlinks=False):
                size = top_entry.stat(follow_symlinks=False).st_size
                root_files_size += size
                _push(biggest, top, size, top_entry.path)
                continue
        except OSError:
            errors += 1
            continue
        total = 0
        stack = [top_entry.path]
        while stack:
            if time.monotonic() > deadline:
                partial = True
                break
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if _skip(e):
                                continue
                            if e.is_dir(follow_symlinks=False):
                                stack.append(e.path)
                            else:
                                size = e.stat(follow_symlinks=False).st_size
                                total += size
                                files += 1
                                _push(biggest, top, size, e.path)
                        except OSError:
                            errors += 1
            except OSError:
                errors += 1
        child_sizes[top_entry.name] = total
    usage = psutil.disk_usage(str(root))
    folders = sorted(child_sizes.items(), key=lambda kv: -kv[1])[:top]
    return {
        "root": str(root),
        "drive_total_gb": round(usage.total / diagnostics.GB, 1),
        "drive_free_gb": round(usage.free / diagnostics.GB, 1),
        "scanned_gb": round((sum(child_sizes.values()) + root_files_size) / diagnostics.GB, 2),
        "files_scanned": files,
        "unreadable_entries": errors,
        "partial": partial,
        "note": "Scan hit the time limit - sizes are lower bounds; re-run on a sub-folder for detail."
        if partial
        else "",
        "largest_folders": [{"folder": name, "size_gb": round(size / diagnostics.GB, 2)} for name, size in folders],
        "largest_files": [
            {"file": p, "size_mb": round(s / diagnostics.MB, 1)} for s, p in sorted(biggest, reverse=True)
        ],
    }


def _skip(entry: os.DirEntry) -> bool:
    if entry.is_symlink():
        return True
    if sys.platform == "win32":
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & _SKIP_ATTRS)
    return entry.path in ("/proc", "/sys", "/dev", "/run")


def _push(heap: list[tuple[int, str]], top: int, size: int, path: str) -> None:
    if len(heap) < top:
        heapq.heappush(heap, (size, path))
    elif size > heap[0][0]:
        heapq.heapreplace(heap, (size, path))
