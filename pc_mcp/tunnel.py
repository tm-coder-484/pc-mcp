"""Expose the local server on a public HTTPS URL with a Cloudflare quick tunnel (no account needed).

cloudflared makes an outbound connection to Cloudflare, so this works behind home routers/NAT and
firewalls without opening ports. The URL is random and changes every time the tunnel starts.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

RELEASES = "https://github.com/cloudflare/cloudflared/releases/latest/download/"
URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def _asset_name() -> str:
    machine = platform.machine().lower()
    arm64 = machine in ("arm64", "aarch64")
    if sys.platform == "win32":
        # No native Windows ARM build is published; the amd64 one runs under emulation.
        return "cloudflared-windows-386.exe" if machine in ("x86", "i386", "i686") else "cloudflared-windows-amd64.exe"
    if sys.platform == "darwin":
        return "cloudflared-darwin-arm64.tgz" if arm64 else "cloudflared-darwin-amd64.tgz"
    if arm64:
        return "cloudflared-linux-arm64"
    if machine.startswith("arm"):
        return "cloudflared-linux-arm"
    if machine in ("i386", "i686", "x86"):
        return "cloudflared-linux-386"
    return "cloudflared-linux-amd64"


def _download(url: str, dest: Path) -> None:
    curl = shutil.which("curl")
    if curl:
        res = subprocess.run([curl, "-fsSL", "--retry", "3", "-o", str(dest), url], capture_output=True, timeout=300)
        if res.returncode == 0:
            return
    # Fall back to Python; some bundled Pythons lack system CAs, so try certifi as well.
    contexts = [ssl.create_default_context()]
    try:
        import certifi

        contexts.append(ssl.create_default_context(cafile=certifi.where()))
    except ImportError:
        pass
    last: Exception | None = None
    for ctx in contexts:
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=120) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
            return
        except Exception as e:  # noqa: BLE001
            last = e
    raise RuntimeError(f"could not download {url}: {last}")


def ensure_cloudflared(bin_dir: Path, log=print) -> str:
    """Return a path to cloudflared, downloading it into bin_dir on first use."""
    existing = shutil.which("cloudflared")
    if existing:
        return existing
    exe_name = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"
    target = bin_dir / exe_name
    if target.exists():
        return str(target)
    bin_dir.mkdir(parents=True, exist_ok=True)
    asset = _asset_name()
    log(f"Downloading cloudflared ({asset}) - one time only...")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_file = Path(tmp) / asset
        _download(RELEASES + asset, tmp_file)
        if asset.endswith(".tgz"):
            with tarfile.open(tmp_file) as tar:
                member = next(m for m in tar.getmembers() if m.name.endswith("cloudflared"))
                member.name = exe_name
                tar.extract(member, bin_dir)
        else:
            shutil.move(str(tmp_file), target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(target)


class QuickTunnel:
    def __init__(self, local_url: str, bin_dir: Path, log_path: Path, log=print) -> None:
        self.local_url = local_url
        self.bin_dir = bin_dir
        self.log_path = log_path
        self.log = log
        self.proc: subprocess.Popen | None = None
        self.public_url: str | None = None
        self.connected = threading.Event()
        self._url_found = threading.Event()
        self._reader: threading.Thread | None = None

    def start(self, timeout: float = 60) -> str:
        exe = ensure_cloudflared(self.bin_dir, self.log)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # cloudflared deliberately shares pc-mcp's console window on Windows, so closing that window ends
        # the tunnel too instead of leaving an orphaned process behind.
        self.proc = subprocess.Popen(
            [exe, "tunnel", "--no-autoupdate", "--url", self.local_url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._reader = threading.Thread(target=self._pump, name="cloudflared-log", daemon=True)
        self._reader.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._url_found.wait(0.25):
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"cloudflared exited early (code {self.proc.returncode}); see {self.log_path}")
        if not self.public_url:
            self.stop()
            raise RuntimeError(f"cloudflared did not produce a URL within {timeout:.0f}s; see {self.log_path}")
        # Give the edge connection a moment so the URL is usable when we print it.
        self.connected.wait(max(0.0, min(20.0, deadline - time.monotonic())))
        return self.public_url

    def _pump(self) -> None:
        assert self.proc and self.proc.stderr
        with open(self.log_path, "ab") as logf:
            for raw in iter(self.proc.stderr.readline, b""):
                logf.write(raw)
                logf.flush()
                line = raw.decode("utf-8", errors="replace")
                if not self.public_url:
                    m = URL_RE.search(line)
                    if m and "api.trycloudflare.com" not in m.group(0):
                        self.public_url = m.group(0)
                        self._url_found.set()
                if "Registered tunnel connection" in line:
                    self.connected.set()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def default_home() -> Path:
    base = os.environ.get("PC_MCP_HOME")
    if base:
        return Path(base)
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "pc-mcp"
    return Path.home() / ".pc-mcp"
