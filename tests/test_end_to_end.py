"""Start the real server (no tunnel) and drive it over HTTP with the bundled client."""

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from pc_mcp import pc_client

TOKEN = "e2e-token-abcdefghijklmnop"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start(tmp_path, *extra):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "pc_mcp", "--no-tunnel", "--port", str(port), "--token", TOKEN, *extra],
        env={**__import__("os").environ, "PC_MCP_HOME": str(tmp_path)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{base}/{TOKEN}/health", timeout=1)
            return proc, base
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(proc.stdout.read())


@pytest.fixture
def server(tmp_path):
    proc, base = _start(tmp_path)
    yield base
    proc.terminate()
    proc.wait(10)


def _tools(url):
    return {t["name"] for t in pc_client.rpc(url, "tools/list")["tools"]}


def _call(url, name, args=None):
    res = pc_client.call_tool(url, name, args or {})
    return res, pc_client.result_payload(res)


def test_full_mode_round_trip(server, tmp_path):
    url = f"{server}/{TOKEN}/mcp"
    init = pc_client.initialize(url)
    assert init["serverInfo"]["name"] == "pc-mcp"
    assert "run_command" in _tools(url)

    _, info = _call(url, "system_info")
    assert info["pc_mcp"]["mode"] == "full"

    cmd = "echo hi" if sys.platform != "win32" else "Write-Output hi"
    res, out = _call(url, "run_command", {"command": cmd})
    assert not res.get("isError") and out["stdout"].strip() == "hi" and out["exit_code"] == 0

    target = tmp_path / "note.txt"
    _call(url, "write_file", {"path": str(target), "content": "hello"})
    _, read = _call(url, "read_file", {"path": str(target)})
    assert read["content"] == "hello"

    res, _ = _call(url, "kill_process", {"pid": 1})
    assert res["isError"]


def test_bad_token_and_client_download(server):
    with pytest.raises(pc_client.RemoteError, match="401"):
        pc_client.initialize(f"{server}/not-the-token-xxxxxxxx/mcp")
    script = urllib.request.urlopen(f"{server}/{TOKEN}/pc.py").read().decode()
    assert script.startswith("#!/usr/bin/env python3") and "def main" in script


def test_read_only_mode_has_no_action_tools(tmp_path):
    proc, base = _start(tmp_path, "--mode", "read-only")
    try:
        tools = _tools(f"{base}/{TOKEN}/mcp")
        assert "diagnose_performance" in tools and "read_file" in tools
        assert not tools & {"run_command", "write_file", "kill_process", "take_screenshot"}
    finally:
        proc.terminate()
        proc.wait(10)


def test_confirm_mode_denies_without_a_person(tmp_path):
    proc, base = _start(tmp_path, "--confirm")
    try:
        res, _ = _call(f"{base}/{TOKEN}/mcp", "run_command", {"command": "echo should-not-run"})
        assert res["isError"] and "denied" in res["content"][0]["text"]
    finally:
        proc.terminate()
        proc.wait(10)


def test_client_accepts_global_options_after_subcommand(server, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pc_client, "CONFIG", tmp_path / "client.json")
    pc_client.main(["call", "system_info", "--url", f"{server}/{TOKEN}/mcp", "--timeout", "60"])
    assert '"pc_mcp"' in capsys.readouterr().out


def test_space_hogs_counts_real_size_of_sparse_files(server, tmp_path):
    sparse = tmp_path / "scan" / "vm" / "disk.img"
    sparse.parent.mkdir(parents=True)
    with open(sparse, "wb") as f:  # 2 GiB logical, a few bytes written
        f.seek(2 * 1024**3)
        f.write(b"x")
    (tmp_path / "scan" / "real.bin").write_bytes(b"y" * 3_000_000)
    _, out = _call(f"{server}/{TOKEN}/mcp", "find_space_hogs", {"path": str(tmp_path / "scan")})
    sizes = {f["file"]: f["size_mb"] for f in out["largest_files"]}
    assert sizes[str(sparse)] < 1, sizes
    assert out["largest_files"][0]["file"].endswith("real.bin")
