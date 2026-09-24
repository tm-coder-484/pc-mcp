"""Running shell commands on this PC: one-shot commands and long-running background jobs."""

from __future__ import annotations

import base64
import html
import itertools
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import psutil

IS_WINDOWS = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000

SHELLS = ("auto", "powershell", "pwsh", "cmd", "bash", "zsh", "sh")

# Windows PowerShell 5.1 writes progress bars to stderr as CLIXML and uses the OEM
# code page when piped; both make captured output unreadable, so switch them off.
_PS_PREAMBLE = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$OutputEncoding=[System.Text.Encoding]::UTF8;"
)


def default_shell() -> str:
    if IS_WINDOWS:
        return "powershell"
    return "bash" if shutil.which("bash") else "sh"


def powershell_exe(prefer: str = "powershell") -> str:
    if IS_WINDOWS and prefer == "powershell":
        return "powershell.exe"
    exe = shutil.which("pwsh") or (shutil.which("powershell") if IS_WINDOWS else None)
    if not exe:
        raise ValueError("PowerShell (pwsh) is not installed on this PC")
    return exe


def build_argv(command: str, shell: str = "auto") -> tuple[list[str] | str, str]:
    """Return (args for Popen, shell label). On Windows cmd gets a raw command line string."""
    shell = (shell or "auto").lower()
    if shell not in SHELLS:
        raise ValueError(f"unknown shell {shell!r}; choose one of {', '.join(SHELLS)}")
    if shell == "auto":
        shell = default_shell()
    if shell in ("powershell", "pwsh"):
        # -EncodedCommand sidesteps every quoting problem between Python, the Windows command line and PowerShell.
        encoded = base64.b64encode((_PS_PREAMBLE + command).encode("utf-16-le")).decode()
        exe = powershell_exe(shell)
        return [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], shell
    if shell == "cmd":
        if not IS_WINDOWS:
            raise ValueError("cmd is only available on Windows")
        # /s strips exactly the outer quotes, so the command itself is passed through verbatim.
        return f'cmd.exe /d /s /c "chcp 65001>nul & {command}"', "cmd"
    exe = shutil.which(shell)
    if not exe:
        raise ValueError(f"{shell} is not installed on this PC")
    return [exe, "-c", command], shell


def _popen_kwargs() -> dict:
    if IS_WINDOWS:
        return {"creationflags": CREATE_NO_WINDOW}
    return {"start_new_session": True}


_CLIXML_BLOCK = re.compile(r"#< CLIXML\s*(<Objs\b.*?</Objs>)", re.S)
_CLIXML_STRING = re.compile(r'<S S="(?:Error|Warning|Verbose|Debug|Information)">(.*?)</S>', re.S)
_CLIXML_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def decode_clixml(text: str) -> str:
    """Windows PowerShell started with -EncodedCommand serialises its error stream as CLIXML
    (`#< CLIXML <Objs>...`); turn those blocks back into the plain text a person would see."""

    def plain(match: re.Match) -> str:
        parts = _CLIXML_STRING.findall(match.group(1))
        text = "".join(html.unescape(_CLIXML_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), p)) for p in parts)
        return text.replace("\r\n", "\n")

    return _CLIXML_BLOCK.sub(plain, text) if "#< CLIXML" in text else text


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    return decode_clixml(data.decode("utf-8", errors="replace").replace("\r\n", "\n"))


def truncate_middle(text: str, limit: int) -> str:
    """Keep the head and (mostly) the tail of long output — errors tend to be at the end."""
    if limit <= 0 or len(text) <= limit:
        return text
    head = limit // 3
    tail = limit - head
    skipped = len(text) - head - tail
    return f"{text[:head]}\n\n... [{skipped:,} characters omitted] ...\n\n{text[-tail:]}"


def kill_tree(pid: int) -> None:
    """Kill a process we started plus everything it spawned. The caller reaps `pid` itself (via Popen), so the
    real exit status is not swallowed by psutil."""
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    children = parent.children(recursive=True)
    for p in [parent, *children]:
        try:
            p.kill()
        except psutil.Error:
            pass
    psutil.wait_procs(children, timeout=5)


def run(
    command: str, shell: str = "auto", cwd: str | None = None, timeout: float = 60, max_output: int = 40_000
) -> dict:
    """Run a command to completion (or until the timeout) and capture its output."""
    argv, label = build_argv(command, shell)
    return run_argv(argv, label, cwd=cwd, timeout=timeout, max_output=max_output)


def run_argv(
    argv: list[str] | str, label: str, cwd: str | None = None, timeout: float = 60, max_output: int = 40_000
) -> dict:
    workdir = os.path.expanduser(cwd) if cwd else None
    if workdir and not os.path.isdir(workdir):
        raise ValueError(f"working directory does not exist: {workdir}")
    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=workdir,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_popen_kwargs(),
    )
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_tree(proc.pid)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
    result = {
        "exit_code": proc.returncode,
        "stdout": truncate_middle(_decode(out), max_output),
        "stderr": truncate_middle(_decode(err), max_output // 2),
        "duration_seconds": round(time.monotonic() - started, 2),
        "shell": label,
    }
    if timed_out:
        result["timed_out"] = True
        result["note"] = (
            f"Killed after {timeout}s. For long-running commands use run_command(..., background=True) "
            "and poll with check_job."
        )
    return result


@dataclass
class Job:
    id: str
    command: str
    shell: str
    cwd: str | None
    log_path: Path
    proc: subprocess.Popen
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    stopped: bool = False

    def status(self) -> str:
        code = self.proc.poll()
        if code is None:
            return "running"
        if self.ended_at is None:
            self.ended_at = time.time()
        return "stopped" if self.stopped else "exited"


class JobManager:
    """Background commands whose output goes to a log file that can be polled."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self._jobs: dict[str, Job] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def start(self, command: str, shell: str = "auto", cwd: str | None = None) -> Job:
        argv, label = build_argv(command, shell)
        workdir = os.path.expanduser(cwd) if cwd else None
        if workdir and not os.path.isdir(workdir):
            raise ValueError(f"working directory does not exist: {workdir}")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            job_id = f"job{next(self._ids)}"
        log_path = self.log_dir / f"{job_id}-{int(time.time())}.log"
        log_file = open(log_path, "wb")  # noqa: SIM115 - handed to the child process
        try:
            proc = subprocess.Popen(
                argv,
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                **_popen_kwargs(),
            )
        finally:
            log_file.close()
        job = Job(job_id, command, label, workdir, log_path, proc)
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Job:
        try:
            return self._jobs[job_id]
        except KeyError:
            known = ", ".join(self._jobs) or "none"
            raise ValueError(f"no job {job_id!r} (known jobs: {known})") from None

    def read_output(self, job: Job, tail_chars: int) -> tuple[str, int]:
        size = job.log_path.stat().st_size if job.log_path.exists() else 0
        with open(job.log_path, "rb") as f:
            if size > tail_chars:
                f.seek(size - tail_chars)
            data = f.read()
        return _decode(data), size

    def describe(self, job: Job, tail_chars: int = 8000) -> dict:
        status = job.status()
        output, size = self.read_output(job, tail_chars)
        end = job.ended_at or time.time()
        info = {
            "job_id": job.id,
            "status": status,
            "exit_code": job.proc.returncode,
            "command": job.command,
            "runtime_seconds": round(end - job.started_at, 1),
            "output_bytes_total": size,
            "output_tail": output,
        }
        if size > tail_chars:
            info["note"] = f"showing the last {tail_chars:,} of {size:,} bytes"
        return info

    def wait(self, job: Job, seconds: float) -> None:
        if seconds > 0:
            try:
                job.proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                pass

    def stop(self, job: Job) -> None:
        if job.proc.poll() is None:
            job.stopped = True
            kill_tree(job.proc.pid)
            job.proc.wait(timeout=10)

    def all(self) -> list[Job]:
        return list(self._jobs.values())

    def stop_all(self) -> None:
        for job in self.all():
            try:
                self.stop(job)
            except Exception:
                pass
