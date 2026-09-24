"""Performance diagnosis: sample the machine, gather OS-specific evidence, and turn it into ranked findings.

Everything here is best-effort. A section that fails (missing permission, missing tool, unsupported OS)
is recorded under ``collection_errors`` and the rest of the report still gets produced.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from pc_mcp import shell

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

GB = 1024**3
MB = 1024**2
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}

# Process names that commonly explain a slow PC, with what to do about them.
KNOWN_HOGS: dict[str, str] = {
    "msmpeng": "Microsoft Defender is scanning. Let it finish, or schedule scans for idle time; add exclusions for big dev/game folders.",
    "mpdefendercoreservice": "Microsoft Defender core service. Usually settles after a scan/update completes.",
    "searchindexer": "Windows Search is indexing files. It calms down once indexing completes; you can limit indexed locations in Settings > Search.",
    "searchprotocolhost": "Windows Search indexing helper; see SearchIndexer.",
    "tiworker": "Windows Update is installing components. Let it finish and restart.",
    "trustedinstaller": "Windows Update / servicing is running. Let it finish and restart.",
    "wuauclt": "Windows Update is running.",
    "usocoreworker": "Windows Update orchestrator is running.",
    "compattelrunner": "Windows compatibility telemetry; runs periodically and ends on its own.",
    "onedrive": "OneDrive is syncing. Pause syncing while you need full speed, or exclude large folders.",
    "dropbox": "Dropbox is syncing. Pause syncing temporarily.",
    "googledrivefs": "Google Drive is syncing.",
    "chrome": "Google Chrome: close unused tabs/extensions (Shift+Esc opens Chrome's own task manager).",
    "msedge": "Microsoft Edge: close unused tabs/extensions (Shift+Esc opens Edge's task manager). Disable 'Startup boost' if unused.",
    "firefox": "Firefox: close unused tabs; about:processes shows per-tab usage.",
    "brave": "Brave: close unused tabs/extensions (Shift+Esc).",
    "teams": "Microsoft Teams is a heavy app; quit it when not needed.",
    "ms-teams": "Microsoft Teams is a heavy app; quit it when not needed.",
    "discord": "Discord: disable hardware acceleration / overlay if it's using a lot.",
    "dwm": "Desktop Window Manager: high usage usually means a graphics driver issue or many high-refresh windows; update the GPU driver.",
    "system": "The Windows 'System' process: high CPU usually points to a driver or disk/storage issue.",
    "wmiprvse": "WMI provider host: another program is querying the system heavily (often monitoring/OEM tools).",
    "antimalware service executable": "Microsoft Defender is scanning.",
    "kernel_task": "macOS kernel_task: high CPU usually means the Mac is hot and throttling on purpose. Improve cooling / check fans.",
    "mds_stores": "Spotlight is indexing; it settles once indexing finishes.",
    "mds": "Spotlight is indexing; it settles once indexing finishes.",
    "mdworker_shared": "Spotlight indexing workers.",
    "photoanalysisd": "Photos library analysis; runs after importing photos, best left to finish while plugged in.",
    "backupd": "Time Machine backup in progress.",
    "cloudd": "iCloud sync in progress.",
    "bird": "iCloud Drive sync in progress.",
    "windowserver": "macOS WindowServer: many displays/windows or transparency effects increase load.",
    "tracker-miner-fs-3": "GNOME file indexer (Tracker); settles after indexing.",
    "baloo_file": "KDE file indexer (Baloo); `balooctl suspend` pauses it.",
    "baloo_file_extractor": "KDE file indexer (Baloo); `balooctl suspend` pauses it.",
    "packagekitd": "PackageKit is checking for / installing updates.",
    "unattended-upgr": "Automatic updates are being installed.",
    "snapd": "snapd is refreshing snaps.",
}


def _key(name: str) -> str:
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


def _cmd(argv: list[str], timeout: float = 15) -> str | None:
    if not shutil.which(argv[0]):
        return None
    try:
        out = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.decode("utf-8", errors="replace")


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return None


def _gb(n: float | int | None) -> float | None:
    return None if n is None else round(n / GB, 1)


def _pct(a: float, b: float) -> float:
    return round(100.0 * a / b, 1) if b else 0.0


# --------------------------------------------------------------------------------------------------
# Machine basics
# --------------------------------------------------------------------------------------------------


def machine_info() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    boot = psutil.boot_time()
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_physical_cores": psutil.cpu_count(logical=False),
        "cpu_logical_cores": psutil.cpu_count(logical=True),
        "ram_total_gb": _gb(vm.total),
        "boot_time": datetime.fromtimestamp(boot).isoformat(timespec="seconds"),
        "uptime_hours": round((time.time() - boot) / 3600, 1),
        "user": _safe(lambda: psutil.Process().username()),
        "is_admin": _is_admin(),
        "python": platform.python_version(),
    }
    if IS_LINUX:
        osr = _read("/etc/os-release") or ""
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)', osr, re.M)
        if m:
            info["os"] = f"{m.group(1)} (kernel {platform.release()})"
        vendor, product = _read("/sys/class/dmi/id/sys_vendor"), _read("/sys/class/dmi/id/product_name")
        if vendor or product:
            info["model"] = f"{vendor or ''} {product or ''}".strip()
        virt = _cmd(["systemd-detect-virt"], 5)
        if virt and virt.strip() and virt.strip() != "none":
            info["virtualization"] = virt.strip()
        elif os.path.exists("/.dockerenv"):
            info["virtualization"] = "docker"
    elif IS_MAC:
        ver = _cmd(["sw_vers", "-productVersion"], 5)
        if ver:
            info["os"] = f"macOS {ver.strip()}"
        model = _cmd(["sysctl", "-n", "hw.model"], 5)
        if model:
            info["model"] = model.strip()
    elif IS_WINDOWS:
        info["os"] = f"Windows {platform.release()} (build {platform.version()})"
    return info


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _cpu_model() -> str:
    if IS_LINUX:
        for line in (_read("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith(("model name", "hardware", "cpu model")):
                return line.split(":", 1)[1].strip()
    if IS_MAC:
        out = _cmd(["sysctl", "-n", "machdep.cpu.brand_string"], 5)
        if out and out.strip():
            return out.strip()
    if IS_WINDOWS:
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return str(winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def _is_admin() -> bool | None:
    try:
        if IS_WINDOWS:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


# --------------------------------------------------------------------------------------------------
# Sampling
# --------------------------------------------------------------------------------------------------

HAS_PROC_IO = hasattr(psutil.Process, "io_counters")
IDLE_NAMES = {"system idle process", "idle", "kernel_idle"}


def _whole_disks() -> set[str] | None:
    """Names of whole block devices on Linux (so partitions/loop devices can be ignored)."""
    if not IS_LINUX:
        return None
    try:
        return {d for d in os.listdir("/sys/block") if not d.startswith(("loop", "ram", "zram", "dm-", "sr", "fd"))}
    except OSError:
        return None


def sample(seconds: float = 5.0) -> dict[str, Any]:
    """Measure CPU, memory, disk, network and per-process usage over a time window."""
    seconds = max(1.0, min(float(seconds), 60.0))
    ncpu = psutil.cpu_count() or 1
    me = os.getpid()

    procs = []
    for p in psutil.process_iter(["pid", "name"]):
        if p.pid in (0, me):
            continue
        try:
            p.cpu_percent(None)
            io0 = p.io_counters() if HAS_PROC_IO else None
        except (psutil.Error, OSError):
            io0 = None
        procs.append((p, io0))

    psutil.cpu_percent(None)
    psutil.cpu_percent(None, percpu=True)
    psutil.cpu_times_percent(None)
    disk0 = _safe(lambda: psutil.disk_io_counters(perdisk=True), {}) or {}
    net0 = _safe(psutil.net_io_counters)
    t0 = time.monotonic()
    time.sleep(seconds)
    elapsed = time.monotonic() - t0

    cpu_total = psutil.cpu_percent(None)
    per_core = psutil.cpu_percent(None, percpu=True)
    times = psutil.cpu_times_percent(None)._asdict()
    disk1 = _safe(lambda: psutil.disk_io_counters(perdisk=True), {}) or {}
    net1 = _safe(psutil.net_io_counters)

    rows = []
    for p, io0 in procs:
        try:
            with p.oneshot():
                name = p.info.get("name") or _safe(p.name) or "?"
                if name.lower() in IDLE_NAMES:
                    continue
                cpu = p.cpu_percent(None)
                mem = p.memory_info()
                row = {
                    "pid": p.pid,
                    "name": name,
                    "cpu_percent_of_total": round(cpu / ncpu, 1),
                    "cpu_percent_of_one_core": round(cpu, 1),
                    "memory_mb": round(mem.rss / MB, 1),
                }
                private = getattr(mem, "private", None)
                if private:
                    row["private_mb"] = round(private / MB, 1)
                if io0 is not None:
                    io1 = p.io_counters()
                    row["disk_read_mb_s"] = round((io1.read_bytes - io0.read_bytes) / MB / elapsed, 2)
                    row["disk_write_mb_s"] = round((io1.write_bytes - io0.write_bytes) / MB / elapsed, 2)
                rows.append(row)
        except (psutil.Error, OSError):
            continue

    whole = _whole_disks()
    disks = []
    for dev, d1 in disk1.items():
        d0 = disk0.get(dev)
        if d0 is None or (whole is not None and dev not in whole):
            continue
        ops = (d1.read_count - d0.read_count) + (d1.write_count - d0.write_count)
        busy_ms = None
        if hasattr(d1, "busy_time"):
            busy_ms = d1.busy_time - d0.busy_time
        elif hasattr(d1, "read_time"):
            busy_ms = (d1.read_time - d0.read_time) + (d1.write_time - d0.write_time)
        io_ms = (d1.read_time - d0.read_time) + (d1.write_time - d0.write_time) if hasattr(d1, "read_time") else None
        disks.append(
            {
                "device": dev,
                "read_mb_s": round((d1.read_bytes - d0.read_bytes) / MB / elapsed, 2),
                "write_mb_s": round((d1.write_bytes - d0.write_bytes) / MB / elapsed, 2),
                "iops": round(ops / elapsed, 1),
                "busy_percent": None if busy_ms is None else min(100.0, round(busy_ms / (elapsed * 10), 1)),
                "avg_latency_ms": round(io_ms / ops, 1) if io_ms is not None and ops >= 5 else None,
            }
        )

    net = None
    if net0 and net1:
        net = {
            "recv_mb_s": round((net1.bytes_recv - net0.bytes_recv) / MB / elapsed, 2),
            "sent_mb_s": round((net1.bytes_sent - net0.bytes_sent) / MB / elapsed, 2),
        }

    return {
        "window_seconds": round(elapsed, 1),
        "cpu_percent": cpu_total,
        "cpu_per_core": per_core,
        "cpu_times_percent": {k: round(v, 1) for k, v in times.items()},
        "processes": rows,
        "process_count": len(procs),
        "disks_io": disks,
        "network": net,
    }


def group_by_app(rows: list[dict]) -> list[dict]:
    apps: dict[str, dict] = defaultdict(lambda: {"instances": 0, "cpu_percent_of_total": 0.0, "memory_mb": 0.0})
    for r in rows:
        a = apps[_key(r["name"])]
        a["name"] = r["name"]
        a["instances"] += 1
        a["cpu_percent_of_total"] += r["cpu_percent_of_total"]
        a["memory_mb"] += r["memory_mb"]
    out = []
    for a in apps.values():
        a["cpu_percent_of_total"] = round(a["cpu_percent_of_total"], 1)
        a["memory_mb"] = round(a["memory_mb"], 1)
        out.append(a)
    return out


# --------------------------------------------------------------------------------------------------
# Static state: memory, volumes, sensors
# --------------------------------------------------------------------------------------------------

_SKIP_FS = {"squashfs", "iso9660", "udf", "tmpfs", "devtmpfs", "overlay", "autofs", "cdfs"}
_SKIP_MOUNT_PREFIXES = (
    "/snap/",
    "/System/Volumes/VM",
    "/System/Volumes/Preboot",
    "/System/Volumes/Update",
    "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot",
    "/System/Volumes/Hardware",
    "/boot/efi",
    "/private/var/vm",
)


def memory_state() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    sw = _safe(psutil.swap_memory)
    out: dict[str, Any] = {
        "total_gb": _gb(vm.total),
        "used_percent": vm.percent,
        "available_gb": _gb(vm.available),
    }
    if sw is not None:
        out.update({"swap_total_gb": _gb(sw.total), "swap_used_gb": _gb(sw.used), "swap_used_percent": sw.percent})
    return out


def volumes() -> list[dict]:
    vols, seen = [], set()
    for part in _safe(lambda: psutil.disk_partitions(all=False), []) or []:
        if part.fstype.lower() in _SKIP_FS or part.mountpoint.startswith(_SKIP_MOUNT_PREFIXES):
            continue
        if IS_WINDOWS and "cdrom" in part.opts:
            continue
        usage = _safe(lambda p=part: psutil.disk_usage(p.mountpoint))
        if usage is None or usage.total < 2 * GB:
            continue
        sig = (usage.total, usage.free)
        if sig in seen:  # APFS/btrfs subvolumes share one pool of space
            continue
        seen.add(sig)
        vols.append(
            {
                "mount": part.mountpoint,
                "device": part.device,
                "fstype": part.fstype,
                "total_gb": _gb(usage.total),
                "free_gb": _gb(usage.free),
                "used_percent": usage.percent,
                "is_system": _is_system_volume(part.mountpoint),
            }
        )
    return vols


def _is_system_volume(mount: str) -> bool:
    if IS_WINDOWS:
        return mount.upper().startswith(os.environ.get("SystemDrive", "C:").upper())
    return mount in ("/", "/System/Volumes/Data")


def temperatures() -> list[dict]:
    fn = getattr(psutil, "sensors_temperatures", None)
    if fn is None:
        return []
    out = []
    for chip, entries in (_safe(fn, {}) or {}).items():
        for e in entries:
            if e.current is None or e.current <= 0:
                continue
            out.append(
                {
                    "sensor": f"{chip}:{e.label or 'temp'}",
                    "celsius": round(e.current, 1),
                    "high": e.high,
                    "critical": e.critical,
                }
            )
    return out


def battery() -> dict | None:
    b = _safe(psutil.sensors_battery)
    if b is None:
        return None
    return {"percent": round(b.percent, 1), "plugged_in": b.power_plugged}


# --------------------------------------------------------------------------------------------------
# OS-specific evidence
# --------------------------------------------------------------------------------------------------

WINDOWS_PROBE = Path(__file__).with_name("windows_probe.ps1")


def windows_evidence() -> dict[str, Any]:
    argv = [
        shell.powershell_exe(),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(WINDOWS_PROBE),
    ]
    res = shell.run_argv(argv, "powershell", timeout=90, max_output=2_000_000)
    text = res["stdout"].strip()
    start = text.find("{")
    if start < 0:
        raise RuntimeError(f"PowerShell probe produced no JSON (exit {res['exit_code']}): {res['stderr'][:500]}")
    return json.loads(text[start:])


def linux_evidence() -> dict[str, Any]:
    ev: dict[str, Any] = {}

    psi = {}
    for res in ("cpu", "memory", "io"):
        txt = _read(f"/proc/pressure/{res}")
        if txt:
            m = re.search(r"some avg10=([\d.]+) avg60=([\d.]+) avg300=([\d.]+)", txt)
            if m:
                psi[res] = {
                    "some_avg10": float(m.group(1)),
                    "some_avg60": float(m.group(2)),
                    "some_avg300": float(m.group(3)),
                }
    if psi:
        ev["pressure_stall"] = psi

    ev["load_average"] = [round(x, 2) for x in os.getloadavg()]

    gov = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    if gov:
        ev["cpu_governor"] = gov
        ev["cpu_freq_driver"] = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver")
    freq = _safe(psutil.cpu_freq)
    if freq and freq.max:
        ev["cpu_freq_mhz"] = {"current": round(freq.current), "max": round(freq.max)}

    disk_types = {}
    for dev in _whole_disks() or ():
        rot = _read(f"/sys/block/{dev}/queue/rotational")
        if rot is not None:
            disk_types[dev] = "HDD" if rot == "1" else "SSD"
    ev["disk_types"] = disk_types
    root_dev = _root_block_device()
    if root_dev:
        ev["system_disk"] = root_dev

    ev["zombie_processes"] = sum(
        1 for p in psutil.process_iter(["status"]) if p.info.get("status") == psutil.STATUS_ZOMBIE
    )

    failed = _cmd(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"], 10)
    if failed is not None:
        ev["failed_units"] = [ln.split()[0] for ln in failed.splitlines() if ln.strip()]

    enabled = _cmd(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"], 10
    )
    if enabled is not None:
        ev["enabled_services"] = len([ln for ln in enabled.splitlines() if ln.strip()])

    analyze = _cmd(["systemd-analyze"], 10)
    if analyze:
        m = re.search(r"=\s*([\dmin. ]+s)\s*$", analyze.splitlines()[0])
        ev["boot_time"] = m.group(1).strip() if m else analyze.splitlines()[0].strip()
        blame = _cmd(["systemd-analyze", "blame", "--no-pager"], 10)
        if blame:
            ev["slowest_boot_units"] = [ln.strip() for ln in blame.splitlines()[:8]]

    autostart = []
    for d in (Path.home() / ".config/autostart", Path("/etc/xdg/autostart")):
        if d.is_dir():
            for f in sorted(d.glob("*.desktop")):
                txt = _safe(lambda f=f: f.read_text(errors="replace"), "") or ""
                if re.search(r"^(Hidden=true|X-GNOME-Autostart-enabled=false)", txt, re.M | re.I):
                    continue
                autostart.append(f.stem)
    ev["autostart_apps"] = autostart

    journal = _cmd(["journalctl", "-p", "3", "--since", "-24h", "-o", "json", "-q", "--no-pager", "-n", "500"], 20)
    if journal is not None:
        counts: dict[str, int] = defaultdict(int)
        samples: dict[str, str] = {}
        for line in journal.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            src = e.get("SYSLOG_IDENTIFIER") or e.get("_SYSTEMD_UNIT") or "kernel"
            counts[src] += 1
            msg = e.get("MESSAGE")
            if isinstance(msg, str):
                samples.setdefault(src, msg[:200])
        ev["errors_last_24h"] = sorted(
            ({"source": s, "count": c, "example": samples.get(s, "")} for s, c in counts.items()),
            key=lambda x: -x["count"],
        )[:10]
    kern = _cmd(["journalctl", "-k", "--since", "-7d", "-o", "cat", "-q", "--no-pager", "-n", "20000"], 20)
    if kern is None:
        kern = _cmd(["dmesg"], 10)
    if kern:
        ev["oom_kills_last_7d"] = len(re.findall(r"Out of memory: Killed process|oom-kill:", kern))
        ev["disk_io_errors_last_7d"] = len(
            re.findall(r"I/O error|blk_update_request|Buffer I/O error|medium error", kern, re.I)
        )
        ev["thermal_throttle_events"] = len(re.findall(r"temperature above threshold|cpu clock throttled", kern, re.I))
    return ev


def _root_block_device() -> str | None:
    try:
        dev = os.stat("/").st_dev
        sys_path = Path(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}").resolve()
    except (OSError, ValueError):
        return None
    for part in reversed(sys_path.parts):
        if Path(f"/sys/block/{part}").exists():
            return part
    return None


def mac_evidence() -> dict[str, Any]:
    ev: dict[str, Any] = {}
    therm = _cmd(["pmset", "-g", "therm"], 10)
    if therm:
        m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", therm)
        ev["cpu_speed_limit_percent"] = int(m.group(1)) if m else 100
        ev["thermal_warning"] = "No thermal warning level" not in therm and "thermal warning level" in therm.lower()
    pm = _cmd(["pmset", "-g"], 10)
    if pm:
        m = re.search(r"lowpowermode\s+(\d)", pm)
        if m:
            ev["low_power_mode"] = m.group(1) == "1"
    mp = _cmd(["memory_pressure", "-Q"], 10)
    if mp:
        m = re.search(r"free percentage:\s*(\d+)%", mp)
        if m:
            ev["memory_free_percent"] = int(m.group(1))
    swap = _cmd(["sysctl", "-n", "vm.swapusage"], 5)
    if swap:
        ev["swap_usage"] = swap.strip()
    di = _cmd(["diskutil", "info", "/"], 10)
    if di:
        m = re.search(r"Solid State:\s*(\w+)", di)
        if m:
            ev["system_disk_ssd"] = m.group(1).lower() == "yes"
    ev["load_average"] = [round(x, 2) for x in os.getloadavg()]
    agents = []
    for d in (Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
        if d.is_dir():
            agents += [f"{d.name}/{f.stem}" for f in d.glob("*.plist") if not f.stem.startswith("com.apple.")]
    ev["third_party_launch_items"] = sorted(agents)
    reports = Path.home() / "Library/Logs/DiagnosticReports"
    if reports.is_dir():
        week_ago = time.time() - 7 * 86400
        crashed: dict[str, int] = defaultdict(int)
        for f in reports.iterdir():
            if _safe(lambda f=f: f.stat().st_mtime, 0) > week_ago and f.suffix in (".ips", ".crash", ".hang", ".diag"):
                crashed[f.name.split("-")[0].split("_")[0]] += 1
        ev["crash_reports_last_7d"] = dict(sorted(crashed.items(), key=lambda kv: -kv[1])[:10])
    return ev


# --------------------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------------------


class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, severity: str, area: str, title: str, detail: str = "", fix: str = "") -> None:
        self.items.append({"severity": severity, "area": area, "title": title, "detail": detail, "fix": fix})

    def sorted(self) -> list[dict]:
        return sorted(self.items, key=lambda f: SEVERITY_ORDER[f["severity"]])


def _hint(name: str) -> str:
    return KNOWN_HOGS.get(_key(name), "")


def _app_label(app: dict, amount: str) -> str:
    return f"{app['name']} x{app['instances']} ({amount})" if app["instances"] > 1 else f"{app['name']} ({amount})"


def analyze(report: dict[str, Any]) -> list[dict]:
    f = Findings()
    s = report["sample"]
    mem = report["memory"]
    info = report["machine"]
    ev = report.get("os_evidence") or {}
    ncpu = info.get("cpu_logical_cores") or 1
    procs = s["processes"]
    apps = group_by_app(procs)

    # ---- CPU ------------------------------------------------------------------------------------
    cpu = s["cpu_percent"]
    top_cpu = sorted(apps, key=lambda a: -a["cpu_percent_of_total"])[:4]
    top_txt = ", ".join(
        _app_label(a, f"{a['cpu_percent_of_total']}%") for a in top_cpu if a["cpu_percent_of_total"] >= 1
    )
    if cpu >= 90:
        f.add(
            "critical",
            "cpu",
            f"CPU is maxed out ({cpu}% over {s['window_seconds']}s)",
            f"Top consumers: {top_txt or 'n/a'}",
            "Close or restart the top consumers; if it is a system process see its specific finding.",
        )
    elif cpu >= 70:
        f.add(
            "warning",
            "cpu",
            f"CPU is heavily loaded ({cpu}%)",
            f"Top consumers: {top_txt or 'n/a'}",
            "Close or pause the top consumers.",
        )

    flagged = set()
    for app in sorted(apps, key=lambda a: -a["cpu_percent_of_total"]):
        if app["cpu_percent_of_total"] < 15:
            break
        flagged.add(_key(app["name"]))
        inst = f" across {app['instances']} processes" if app["instances"] > 1 else ""
        sev = "critical" if app["cpu_percent_of_total"] >= 50 else "warning"
        f.add(
            sev,
            "cpu",
            f"{app['name']} is using {app['cpu_percent_of_total']}% of total CPU{inst}",
            _hint(app["name"]),
            "End or restart it if it is not doing something you need." if not _hint(app["name"]) else "",
        )
    for r in procs:
        if _key(r["name"]) in flagged or ncpu < 4:
            continue
        if r["cpu_percent_of_one_core"] >= 90:
            flagged.add(_key(r["name"]))
            f.add(
                "warning",
                "cpu",
                f"{r['name']} (PID {r['pid']}) is pegging a full CPU core ({r['cpu_percent_of_one_core']}% of one core)",
                "A single-threaded process stuck at 100% of a core is often a runaway/hung program. "
                + _hint(r["name"]),
                "Restart that program if it is not actively working on something.",
            )

    times = s.get("cpu_times_percent", {})
    irq = times.get("interrupt", 0) + times.get("dpc", 0)
    if IS_WINDOWS and irq >= 10:
        f.add(
            "warning",
            "drivers",
            f"High interrupt/DPC time ({irq:.0f}% of CPU)",
            "Time spent servicing hardware interrupts is usually caused by a faulty or outdated driver (network, audio, storage, GPU) or failing hardware.",
            "Update chipset/network/audio/GPU drivers; LatencyMon can pinpoint the driver.",
        )
    if times.get("iowait", 0) >= 20:
        f.add(
            "warning",
            "disk",
            f"CPU is spending {times['iowait']}% of its time waiting on disk I/O",
            "The disk, not the CPU, is the bottleneck.",
            "See the disk findings / top disk I/O processes.",
        )
    if times.get("steal", 0) >= 10:
        f.add(
            "warning",
            "virtualization",
            f"CPU steal time is {times['steal']}%",
            "This is a virtual machine and the host is overcommitted.",
            "Give the VM more dedicated CPU or move it to a less busy host.",
        )

    load = ev.get("load_average")
    if load and not IS_WINDOWS and load[0] / ncpu >= 2:
        f.add(
            "warning",
            "cpu",
            f"Load average {load[0]} is {load[0] / ncpu:.1f}x the {ncpu} CPU threads",
            "More work is queued than the CPU can run.",
            "Find the processes queued on CPU or disk (see top processes).",
        )

    psi = ev.get("pressure_stall", {})
    if psi.get("memory", {}).get("some_avg10", 0) >= 10:
        f.add(
            "warning",
            "memory",
            f"Tasks stalled on memory {psi['memory']['some_avg10']}% of the time (last 10s)",
            "Linux pressure-stall info shows programs waiting for memory to be freed.",
            "Close memory-heavy apps or add RAM/swap.",
        )
    if psi.get("io", {}).get("some_avg10", 0) >= 25:
        f.add(
            "warning",
            "disk",
            f"Tasks stalled on disk I/O {psi['io']['some_avg10']}% of the time (last 10s)",
            "",
            "See top disk I/O processes.",
        )
    if psi.get("cpu", {}).get("some_avg10", 0) >= 50:
        f.add("warning", "cpu", f"Tasks waited for CPU {psi['cpu']['some_avg10']}% of the time (last 10s)", "", "")

    # ---- CPU speed / power ----------------------------------------------------------------------
    perf = ev.get("processor_performance_percent")
    if perf is not None and perf < 60 and cpu >= 25:
        f.add(
            "warning",
            "power",
            f"CPU is running at only {perf}% of its rated speed while busy",
            "The processor is being throttled: power-saving plan, battery saver, or overheating.",
            "Plug in the charger, switch Power mode to 'Best performance', and check cooling (dust, blocked vents).",
        )
    limit = ev.get("cpu_speed_limit_percent")
    if limit is not None and limit < 100:
        f.add(
            "critical" if limit < 70 else "warning",
            "thermal",
            f"macOS is limiting CPU speed to {limit}% because of heat",
            "The Mac is thermally throttling.",
            "Improve airflow, clean vents/fans, avoid soft surfaces; check with an SMC reset on Intel Macs.",
        )
    plan = (ev.get("power_plan") or {}).get("name", "")
    plan_guid = (ev.get("power_plan") or {}).get("guid", "")
    if plan_guid == "a1841308-3541-4fab-bc81-f71556f20b4a" or "saver" in plan.lower():
        f.add(
            "warning",
            "power",
            f"Power plan is '{plan}'",
            "Power saver caps CPU speed.",
            "Control Panel > Power Options > Balanced or High performance.",
        )
    overlay = (ev.get("power_plan") or {}).get("power_mode")
    if overlay == "Best power efficiency":
        f.add(
            "info",
            "power",
            "Windows Power mode is 'Best power efficiency'",
            "This trades speed for battery life.",
            "Settings > System > Power & battery > Power mode > Balanced or Best performance.",
        )
    if ev.get("low_power_mode"):
        f.add(
            "info",
            "power",
            "macOS Low Power Mode is on",
            "It reduces CPU speed.",
            "System Settings > Battery > Low Power Mode > Never/Only on battery.",
        )
    gov, drv = ev.get("cpu_governor"), ev.get("cpu_freq_driver") or ""
    if gov == "powersave" and "pstate" not in drv:
        f.add(
            "info",
            "power",
            "CPU frequency governor is 'powersave'",
            f"With the {drv or 'current'} driver this pins the CPU to its lowest speed.",
            "Switch to 'schedutil' or 'ondemand' (e.g. `cpupower frequency-set -g schedutil`).",
        )
    bat = report.get("battery")
    if bat and not bat["plugged_in"] and bat["percent"] < 20:
        f.add(
            "info",
            "power",
            f"Running on battery at {bat['percent']}%",
            "Battery saver modes throttle the CPU.",
            "Plug in the charger.",
        )
    for t in report.get("temperatures", []):
        limit_c = t["critical"] or t["high"] or 95
        if t["celsius"] >= min(limit_c, 95) or t["celsius"] >= 90:
            f.add(
                "warning",
                "thermal",
                f"{t['sensor']} is at {t['celsius']}°C",
                "Hot CPUs throttle themselves.",
                "Clean dust from fans/heatsink; check fans spin; re-paste if old.",
            )
            break
    if ev.get("thermal_throttle_events"):
        f.add(
            "warning",
            "thermal",
            f"{ev['thermal_throttle_events']} CPU thermal-throttle events in the kernel log",
            "",
            "Improve cooling.",
        )

    # ---- Memory ---------------------------------------------------------------------------------
    used, avail = mem["used_percent"], mem["available_gb"]
    top_mem_apps = [a for a in sorted(apps, key=lambda a: -a["memory_mb"])[:5] if a["memory_mb"] >= 100]
    mem_txt = ", ".join(_app_label(a, f"{a['memory_mb'] / 1024:.1f} GB") for a in top_mem_apps)
    if used >= 95 or (avail is not None and avail < 0.5):
        f.add(
            "critical",
            "memory",
            f"RAM is almost full ({used}% used, {avail} GB available)",
            f"Biggest users: {mem_txt}",
            "Close the biggest apps/browser tabs. If this is normal usage, the PC needs more RAM.",
        )
    elif used >= 85:
        f.add(
            "warning",
            "memory",
            f"RAM is under pressure ({used}% used, {avail} GB available)",
            f"Biggest users: {mem_txt}",
            "Close unused apps and browser tabs.",
        )
    total_mb = (mem["total_gb"] or 0) * 1024
    for a in top_mem_apps:
        share = _pct(a["memory_mb"], total_mb)
        if share >= 25 and used >= 70:
            inst = f" across {a['instances']} processes" if a["instances"] > 1 else ""
            f.add(
                "warning",
                "memory",
                f"{a['name']} is using {a['memory_mb'] / 1024:.1f} GB ({share:.0f}% of RAM){inst}",
                _hint(a["name"]),
                "" if _hint(a["name"]) else "Close it or restart it if it has grown over time (memory leak).",
            )
    if mem.get("swap_used_percent", 0) >= 50 and used >= 80 and (mem.get("swap_total_gb") or 0) > 0.5:
        f.add(
            "warning",
            "memory",
            f"Heavy use of the page/swap file ({mem['swap_used_gb']} GB, {mem['swap_used_percent']}%)",
            "Memory is spilling to disk, which is much slower than RAM.",
            "Close memory-heavy apps; consider more RAM.",
        )
    commit = ev.get("commit")
    if commit and commit.get("used_percent", 0) >= 90:
        f.add(
            "critical",
            "memory",
            f"Windows commit charge is at {commit['used_percent']}% of the limit",
            f"{commit.get('used_gb')} GB committed of {commit.get('limit_gb')} GB. Programs will fail to allocate memory and the system will hang.",
            "Close memory-heavy apps; make sure the page file is 'System managed'.",
        )
    if ev.get("low_memory_events_7d"):
        f.add(
            "critical",
            "memory",
            f"Windows logged {ev['low_memory_events_7d']} 'low virtual memory' events in the last 7 days",
            "",
            "The PC is regularly running out of memory: add RAM or reduce what runs at once.",
        )
    total_gb = mem["total_gb"] or 0
    if total_gb and total_gb <= 4.5:
        f.add(
            "warning",
            "hardware",
            f"Only {total_gb} GB of RAM installed",
            "Modern OSes and browsers need 8 GB+ to feel responsive.",
            "Upgrade RAM if the PC allows it.",
        )
    elif total_gb and total_gb <= 8.5 and IS_WINDOWS and used >= 75:
        f.add(
            "info",
            "hardware",
            f"{total_gb} GB of RAM is tight for this workload",
            "",
            "16 GB is comfortable for browser-heavy multitasking on Windows 11.",
        )
    mfree = ev.get("memory_free_percent")
    if mfree is not None and mfree < 15:
        f.add(
            "warning",
            "memory",
            f"macOS memory pressure is high ({mfree}% free)",
            f"Biggest users: {mem_txt}",
            "Close memory-heavy apps.",
        )
    if ev.get("oom_kills_last_7d"):
        f.add(
            "warning",
            "memory",
            f"The kernel killed {ev['oom_kills_last_7d']} processes for lack of memory in the last 7 days",
            "",
            "Add RAM or swap, or reduce the workload.",
        )

    # ---- Disks ----------------------------------------------------------------------------------
    for v in report["volumes"]:
        free, pct = v["free_gb"], v["used_percent"]
        label = f"{v['mount']}{' (system drive)' if v['is_system'] else ''}"
        if (v["is_system"] and (free < 5 or pct >= 97)) or free < 1:
            f.add(
                "critical",
                "disk",
                f"{label} is almost full: {free} GB free ({pct}% used)",
                "A nearly-full system drive slows everything down (no room for page file, updates, temp files).",
                "Free space: empty Recycle Bin/Downloads, run Disk Cleanup / Storage Sense, uninstall unused apps (use find_space_hogs to locate big folders).",
            )
        elif (v["is_system"] and (free < 15 or pct >= 90)) or pct >= 95:
            f.add(
                "warning",
                "disk",
                f"{label} is low on space: {free} GB free ({pct}% used)",
                "",
                "Free up space (find_space_hogs shows the biggest folders).",
            )

    disk_types = ev.get("disk_types") or {}
    sys_disk_hdd = False
    for pd in ev.get("physical_disks", []):
        if pd.get("health") not in (None, "", "Healthy"):
            f.add(
                "critical",
                "disk",
                f"Disk '{pd.get('name')}' health is {pd.get('health')}",
                "The drive is reporting problems.",
                "Back up now and replace the drive.",
            )
        if pd.get("media_type") == "HDD" and pd.get("is_system"):
            sys_disk_hdd = True
    virtual_disk = False
    if ev.get("system_disk") and disk_types.get(ev["system_disk"]) == "HDD":
        # Virtual disks (virtio/xen/VM guests) report "rotational" regardless of the real storage behind them.
        virtual_disk = bool(info.get("virtualization")) or ev["system_disk"].startswith(("vd", "xvd"))
        sys_disk_hdd = not virtual_disk
    if ev.get("system_disk_ssd") is False:
        sys_disk_hdd = True
    if virtual_disk:
        f.add(
            "info",
            "hardware",
            f"System disk {ev['system_disk']} is a virtual disk",
            "This is a VM/container, so the real storage type is decided by the host.",
            "",
        )
    if sys_disk_hdd:
        f.add(
            "warning",
            "hardware",
            "The system drive is a spinning hard disk (HDD)",
            "HDDs are 10-100x slower than SSDs for the random reads an OS does; this is the #1 cause of slow boot and app launch on older PCs.",
            "Clone the system onto an SSD - the single biggest speed-up for this PC.",
        )
    io_rows = sorted(
        (r for r in procs if "disk_read_mb_s" in r), key=lambda r: -(r["disk_read_mb_s"] + r["disk_write_mb_s"])
    )
    io_rows = [r for r in io_rows if r["disk_read_mb_s"] + r["disk_write_mb_s"] >= 1][:3]
    io_txt = ", ".join(f"{r['name']} ({r['disk_read_mb_s'] + r['disk_write_mb_s']:.0f} MB/s)" for r in io_rows)
    disk_busy = False
    for d in s["disks_io"]:
        busy, lat = d.get("busy_percent"), d.get("avg_latency_ms")
        if busy is not None and busy >= 75:
            disk_busy = True
            f.add(
                "critical" if busy >= 95 else "warning",
                "disk",
                f"Disk {d['device']} was {busy}% busy",
                f"Top disk users: {io_txt or 'not attributable to a process (per-process I/O needs admin, or this OS lacks it)'}",
                "The disk is saturated; see the processes named (often updates, antivirus scans, indexing, sync or backups).",
            )
        if lat is not None and lat >= 50:
            disk_busy = True
            f.add(
                "critical" if lat >= 200 else "warning",
                "disk",
                f"Disk {d['device']} average response time is {lat} ms",
                "Healthy SSDs answer in under 5 ms and HDDs in 5-20 ms under light load."
                + (f" Top disk users: {io_txt}." if io_txt else ""),
                "If one process is hammering the disk, pause/stop it; if nothing is, the drive may be failing: check its health and back up.",
            )
    for r in io_rows:
        rate = r["disk_read_mb_s"] + r["disk_write_mb_s"]
        if rate >= 50 or (disk_busy and rate >= 10):
            f.add(
                "warning",
                "disk",
                f"{r['name']} (PID {r['pid']}) is {'writing' if r['disk_write_mb_s'] >= r['disk_read_mb_s'] else 'reading'} {rate:.0f} MB/s",
                _hint(r["name"]),
                "" if _hint(r["name"]) else "Pause or stop it while you need the PC to be responsive.",
            )
    if ev.get("disk_errors_7d") or ev.get("disk_io_errors_last_7d"):
        n = ev.get("disk_errors_7d") or ev.get("disk_io_errors_last_7d")
        f.add(
            "critical",
            "disk",
            f"{n} disk/storage errors logged in the last 7 days",
            "Storage errors often precede drive failure and cause freezes.",
            "Back up important files now; check the drive's SMART health (CrystalDiskInfo on Windows).",
        )

    # ---- Startup, uptime, updates -----------------------------------------------------------------
    up = info.get("uptime_hours", 0)
    if up >= 24 * 14:
        note = (
            " (Windows 'Fast startup' means Shut down does not reset this - use Restart.)"
            if ev.get("fast_startup")
            else ""
        )
        f.add(
            "warning",
            "uptime",
            f"Not restarted in {up / 24:.0f} days",
            "Long uptimes accumulate leaked memory and pending updates." + note,
            "Restart the PC.",
        )
    elif up >= 24 * 5:
        f.add(
            "info",
            "uptime",
            f"Up for {up / 24:.0f} days",
            "A restart often clears slowness.",
            "Restart when convenient.",
        )
    if ev.get("pending_reboot"):
        f.add("warning", "updates", "A restart is pending to finish installing updates", "", "Restart the PC.")
    startup = ev.get("startup_apps")
    if startup is None:
        startup = ev.get("autostart_apps")
    if startup:
        names = [s_["name"] if isinstance(s_, dict) else s_ for s_ in startup]
        if len(names) >= 12:
            f.add(
                "warning",
                "startup",
                f"{len(names)} programs start automatically",
                ", ".join(names[:20]),
                "Disable the ones you don't need (Task Manager > Startup apps on Windows).",
            )
        elif len(names) >= 7:
            f.add(
                "info",
                "startup",
                f"{len(names)} programs start automatically",
                ", ".join(names),
                "Disable the ones you don't need.",
            )
    tp = ev.get("third_party_launch_items")
    if tp and len(tp) >= 15:
        f.add(
            "info",
            "startup",
            f"{len(tp)} third-party launch agents/daemons installed",
            ", ".join(tp[:20]),
            "Remove leftovers from uninstalled apps.",
        )
    boot_ms = ev.get("last_boot_duration_ms")
    if boot_ms and boot_ms >= 90_000:
        culprits = ", ".join(ev.get("slow_boot_culprits", [])[:5])
        f.add(
            "warning",
            "startup",
            f"Last boot took {boot_ms / 1000:.0f} s",
            f"Slow-boot culprits logged by Windows: {culprits or 'none recorded'}",
            "Trim startup apps; an SSD helps most.",
        )
    avs = ev.get("antivirus_products") or []
    if len(avs) >= 2:
        f.add(
            "warning",
            "security-software",
            f"{len(avs)} antivirus products registered: {', '.join(avs)}",
            "Multiple real-time scanners fight over every file access.",
            "Keep one antivirus and fully uninstall the others.",
        )

    # ---- Misc ---------------------------------------------------------------------------------------
    if ev.get("failed_units"):
        f.add(
            "info",
            "services",
            f"{len(ev['failed_units'])} failed systemd units",
            ", ".join(ev["failed_units"][:10]),
            "`systemctl status <unit>` for details.",
        )
    if ev.get("zombie_processes", 0) >= 20:
        f.add(
            "info",
            "processes",
            f"{ev['zombie_processes']} zombie processes",
            "A parent process isn't reaping its children.",
            "Restart the parent program.",
        )
    whea = ev.get("hardware_errors_7d")
    if whea:
        f.add(
            "warning",
            "hardware",
            f"{whea} hardware (WHEA) errors in the last 7 days",
            "CPU, RAM or PCIe devices are reporting corrected/uncorrected errors.",
            "Check for BIOS/chipset updates, undo overclocks, run Windows Memory Diagnostic.",
        )
    if ev.get("unexpected_shutdowns_7d"):
        f.add(
            "info",
            "stability",
            f"{ev['unexpected_shutdowns_7d']} unexpected shutdowns/crashes in the last 7 days",
            "",
            "Check power supply, overheating and recent driver changes.",
        )
    hangs = ev.get("app_hangs_7d") or {}
    if hangs:
        f.add(
            "info",
            "stability",
            "Apps that hung or crashed in the last 7 days",
            ", ".join(f"{k} ({v})" for k, v in list(hangs.items())[:8]),
            "Update or reinstall the repeat offenders.",
        )
    crashes = ev.get("crash_reports_last_7d") or {}
    if crashes:
        f.add(
            "info",
            "stability",
            "Apps with crash/hang reports in the last 7 days",
            ", ".join(f"{k} ({v})" for k, v in crashes.items()),
            "",
        )
    net = s.get("network") or {}
    if (net.get("recv_mb_s") or 0) + (net.get("sent_mb_s") or 0) >= 5:
        f.add(
            "info",
            "network",
            f"Heavy network traffic: {net['recv_mb_s']} MB/s down, {net['sent_mb_s']} MB/s up",
            "Something is downloading/uploading (updates, cloud sync, backups, game launchers).",
            "",
        )
    same = [a for a in apps if a["instances"] >= 25]
    for a in same:
        f.add(
            "info",
            "processes",
            f"{a['instances']} instances of {a['name']} using {a['memory_mb'] / 1024:.1f} GB together",
            _hint(a["name"]),
            "",
        )
    return f.sorted()


def summarize(findings: list[dict], info: dict) -> str:
    crit = [x for x in findings if x["severity"] == "critical"]
    warn = [x for x in findings if x["severity"] == "warning"]
    head = f"{info.get('hostname')} ({info.get('os')}): "
    if not crit and not warn:
        return head + (
            "No obvious performance problem found during the sample window. If the slowness is intermittent, "
            "run diagnose_performance again while it is happening."
        )
    parts = [f"{len(crit)} critical, {len(warn)} warning findings."]
    parts += [f"- [{x['severity'].upper()}] {x['title']}" for x in (crit + warn)[:6]]
    return head + "\n".join(parts)


def diagnose(sample_seconds: float = 5.0, include_os_checks: bool = True) -> dict[str, Any]:
    errors: list[str] = []
    started = time.monotonic()
    report: dict[str, Any] = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    report["machine"] = machine_info()
    report["sample"] = sample(sample_seconds)
    report["memory"] = memory_state()
    report["volumes"] = volumes()
    report["temperatures"] = temperatures()
    report["battery"] = battery()
    ev: dict[str, Any] = {}
    if include_os_checks:
        try:
            if IS_WINDOWS:
                ev = windows_evidence()
            elif IS_LINUX:
                ev = linux_evidence()
            elif IS_MAC:
                ev = mac_evidence()
        except Exception as e:  # noqa: BLE001 - report and carry on
            errors.append(f"os checks: {e}")
        errors += ev.pop("errors", []) if isinstance(ev.get("errors"), list) else []
    if IS_WINDOWS and ev:
        _windows_postprocess(report, ev)
    report["os_evidence"] = ev

    findings = analyze(report)

    procs = report["sample"].pop("processes")
    report["sample"]["top_by_cpu"] = sorted(procs, key=lambda r: -r["cpu_percent_of_total"])[:12]
    report["sample"]["top_by_memory"] = sorted(procs, key=lambda r: -r["memory_mb"])[:12]
    if HAS_PROC_IO:
        report["sample"]["top_by_disk_io"] = [
            r
            for r in sorted(procs, key=lambda r: -(r.get("disk_read_mb_s", 0) + r.get("disk_write_mb_s", 0)))[:8]
            if r.get("disk_read_mb_s", 0) + r.get("disk_write_mb_s", 0) > 0
        ]
    apps = group_by_app(procs)
    report["sample"]["top_apps_by_memory"] = sorted(apps, key=lambda a: -a["memory_mb"])[:10]
    report["sample"]["top_apps_by_cpu"] = [
        a for a in sorted(apps, key=lambda a: -a["cpu_percent_of_total"])[:10] if a["cpu_percent_of_total"] > 0
    ]
    if IS_WINDOWS:
        _annotate_svchost(report["sample"]["top_by_cpu"])

    report["findings"] = findings
    report["summary"] = summarize(findings, report["machine"])
    report["collection_errors"] = errors
    report["diagnosis_seconds"] = round(time.monotonic() - started, 1)
    # Put the answer first for whoever reads the JSON.
    ordered = {k: report[k] for k in ("summary", "findings")}
    ordered.update({k: v for k, v in report.items() if k not in ordered})
    return ordered


def _windows_postprocess(report: dict[str, Any], ev: dict[str, Any]) -> None:
    plan = ev.get("power_plan")
    if isinstance(plan, dict):
        bat = report.get("battery")
        on_ac = bat is None or bat["plugged_in"]
        plan["power_mode"] = plan.get("power_mode_ac" if on_ac else "power_mode_dc")
    for c in ev.get("acpi_thermal_c") or []:
        if isinstance(c, (int, float)) and 20 <= c <= 125:
            report["temperatures"].append({"sensor": "ACPI thermal zone", "celsius": c, "high": None, "critical": None})
    if ev.get("model"):
        report["machine"]["model"] = f"{ev.get('manufacturer', '')} {ev['model']}".strip()
    if ev.get("os_caption"):
        report["machine"]["os"] = f"{ev['os_caption']} (build {ev.get('os_build', '?')})"


def _annotate_svchost(rows: list[dict]) -> None:
    """svchost.exe is a container for services; name the services living in the busy ones."""
    targets = {r["pid"]: r for r in rows if _key(r["name"]) == "svchost" and r["cpu_percent_of_total"] >= 2}
    if not targets:
        return
    try:
        for svc in psutil.win_service_iter():  # type: ignore[attr-defined]
            try:
                pid = svc.pid()
                if pid in targets:
                    targets[pid].setdefault("services", []).append(f"{svc.name()} ({svc.display_name()})")
            except psutil.Error:
                continue
    except Exception:
        pass
