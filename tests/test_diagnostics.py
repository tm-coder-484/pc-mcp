import json
import shutil
import subprocess
from pathlib import Path

import pytest

from pc_mcp import diagnostics

HERE = Path(__file__).parent


def _report(processes=None, cpu=5.0, mem_used=40.0, avail=8.0, volumes=None, disks_io=None, ev=None, times=None):
    return {
        "machine": {"hostname": "test-pc", "os": "TestOS", "cpu_logical_cores": 8, "uptime_hours": 10},
        "sample": {
            "window_seconds": 5,
            "cpu_percent": cpu,
            "cpu_times_percent": times or {},
            "processes": processes or [],
            "process_count": len(processes or []),
            "disks_io": disks_io or [],
            "network": {"recv_mb_s": 0, "sent_mb_s": 0},
        },
        "memory": {"total_gb": 16.0, "used_percent": mem_used, "available_gb": avail, "swap_used_percent": 0},
        "volumes": volumes or [],
        "temperatures": [],
        "battery": None,
        "os_evidence": ev or {},
    }


def _proc(name, cpu=0.0, mem=100.0, pid=1000, write=0.0):
    return {
        "pid": pid,
        "name": name,
        "cpu_percent_of_total": cpu,
        "cpu_percent_of_one_core": cpu * 8,
        "memory_mb": mem,
        "disk_read_mb_s": 0.0,
        "disk_write_mb_s": write,
    }


def titles(findings):
    return [f["title"] for f in findings]


def test_diagnose_runs_on_this_machine():
    r = diagnostics.diagnose(sample_seconds=1)
    assert list(r)[:2] == ["summary", "findings"]
    assert r["machine"]["cpu_logical_cores"] >= 1
    assert "top_by_cpu" in r["sample"] and "processes" not in r["sample"]
    for f in r["findings"]:
        assert f["severity"] in ("critical", "warning", "info")
    json.dumps(r)  # must be serialisable for MCP


def test_healthy_machine_has_no_warnings():
    findings = diagnostics.analyze(_report(processes=[_proc("editor", 2.0)]))
    assert not [f for f in findings if f["severity"] != "info"]
    assert "No obvious performance problem" in diagnostics.summarize(findings, {"hostname": "x", "os": "y"})


def test_cpu_hogs_are_named_and_grouped():
    procs = [_proc("MsMpEng.exe", 40.0, pid=1), _proc("chrome.exe", 10.0, pid=2), _proc("chrome.exe", 10.0, pid=3)]
    findings = diagnostics.analyze(_report(processes=procs, cpu=75))
    t = titles(findings)
    assert "CPU is heavily loaded (75%)" in t
    assert any(x.startswith("MsMpEng.exe is using 40.0%") for x in t)
    assert any(x.startswith("chrome.exe is using 20.0% of total CPU across 2 processes") for x in t)
    defender = next(f for f in findings if f["title"].startswith("MsMpEng"))
    assert "Defender" in defender["detail"]


def test_memory_pressure_and_big_app():
    procs = [_proc("chrome.exe", mem=900.0, pid=i) for i in range(12)]
    findings = diagnostics.analyze(_report(processes=procs, mem_used=96, avail=0.4))
    t = titles(findings)
    assert any(x.startswith("RAM is almost full") for x in t)
    assert any(x.startswith("chrome.exe is using 10.5 GB") and "12 processes" in x for x in t)
    assert findings[0]["severity"] == "critical"


def test_low_disk_space_on_system_drive():
    vols = [
        {"mount": "C:\\", "free_gb": 3.2, "used_percent": 98.6, "is_system": True},
        {"mount": "D:\\", "free_gb": 400.0, "used_percent": 20.0, "is_system": False},
    ]
    findings = diagnostics.analyze(_report(volumes=vols))
    crit = [f for f in findings if f["severity"] == "critical"]
    assert len(crit) == 1 and crit[0]["title"].startswith("C:\\ (system drive) is almost full")


def test_busy_disk_names_the_process():
    procs = [_proc("OneDrive.exe", pid=77, write=120.0)]
    io = [{"device": "PhysicalDrive0", "busy_percent": 99.0, "avg_latency_ms": 250.0}]
    t = titles(diagnostics.analyze(_report(processes=procs, disks_io=io)))
    assert "Disk PhysicalDrive0 was 99.0% busy" in t
    assert "OneDrive.exe (PID 77) is writing 120 MB/s" in t


def test_windows_evidence_findings():
    ev = json.loads((HERE / "fixtures" / "windows_evidence.json").read_text())
    report = _report(processes=[_proc("Code.exe", 20.0)], cpu=35, ev=ev)
    report["machine"]["uptime_hours"] = 24 * 20
    t = " | ".join(titles(diagnostics.analyze(report)))
    for expected in [
        "Windows commit charge is at 93.8% of the limit",
        "'low virtual memory' events",
        "CPU is running at only 42% of its rated speed while busy",
        "Power plan is 'Power saver'",
        "The system drive is a spinning hard disk (HDD)",
        "Disk 'USB Stick' health is Warning",
        "4 disk/storage errors logged in the last 7 days",
        "2 hardware (WHEA) errors",
        "2 antivirus products registered: Windows Defender, Norton 360",
        "13 programs start automatically",
        "A restart is pending",
        "Not restarted in 20 days",
        "Last boot took 123 s",
        "Apps that hung or crashed",
    ]:
        assert expected in t, expected


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell 7 (pwsh) not installed")
def test_windows_probe_against_mocked_cmdlets():
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HERE / "windows_probe_mock.ps1")],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout
    ev = json.loads(out)
    assert ev["power_plan"] == {
        "guid": "a1841308-3541-4fab-bc81-f71556f20b4a",
        "name": "Power saver",
        "power_mode_ac": "Best power efficiency",
    }
    assert ev["commit"]["used_percent"] == 93.8
    assert [d["is_system"] for d in ev["physical_disks"]] == [True, False]
    assert ev["disk_errors_7d"] == 4 and ev["hardware_errors_7d"] == 2 and ev["low_memory_events_7d"] == 3
    assert ev["unexpected_shutdowns_7d"] == 1
    assert ev["app_hangs_7d"] == {"chrome.exe": 3, "Teams.exe": 1}
    assert len(ev["startup_apps"]) == 13 and ev["startup_apps_disabled"] == 1
    assert ev["antivirus_products"] == ["Windows Defender", "Norton 360"]
    assert ev["last_boot_duration_ms"] == 123456
    assert ev["pending_reboot"] is True and ev["fast_startup"] is True
    assert ev["acpi_thermal_c"] == [95.1]
    assert [e for e in ev["errors"] if not e.startswith("is_admin")] == []
