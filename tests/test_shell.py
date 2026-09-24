import base64
import sys

import pytest

from pc_mcp import shell

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX shell syntax")


@posix_only
def test_run_captures_output_and_exit_code():
    r = shell.run('echo "a \\"quoted\\" word"; echo err >&2; exit 3')
    assert r["stdout"] == 'a "quoted" word\n'
    assert r["stderr"] == "err\n"
    assert r["exit_code"] == 3


@posix_only
def test_timeout_kills_and_reports_nonzero():
    r = shell.run("sleep 5; echo never", timeout=1)
    assert r["timed_out"] is True
    assert r["exit_code"] != 0
    assert "never" not in r["stdout"]


@posix_only
def test_cwd_is_respected(tmp_path):
    assert shell.run("pwd", cwd=str(tmp_path))["stdout"].strip() == str(tmp_path)
    with pytest.raises(ValueError):
        shell.run("pwd", cwd=str(tmp_path / "missing"))


def test_truncate_middle_keeps_head_and_tail():
    text = "A" * 1000 + "B" * 1000
    out = shell.truncate_middle(text, 300)
    assert out.startswith("A" * 100) and out.endswith("B" * 200)
    assert "omitted" in out
    assert shell.truncate_middle("short", 300) == "short"


def test_powershell_commands_are_base64_encoded(monkeypatch):
    monkeypatch.setattr(shell, "powershell_exe", lambda prefer="powershell": "pwsh")
    argv, label = shell.build_argv('Write-Output "it\'s \\"fine\\""', "powershell")
    assert label == "powershell" and argv[-2] == "-EncodedCommand"
    decoded = base64.b64decode(argv[-1]).decode("utf-16-le")
    assert decoded.endswith('Write-Output "it\'s \\"fine\\""')
    assert "$ProgressPreference" in decoded


def test_unknown_shell_rejected():
    with pytest.raises(ValueError):
        shell.build_argv("x", "fish")


@pytest.mark.skipif(sys.platform == "win32", reason="cmd exists on Windows")
def test_cmd_rejected_off_windows():
    with pytest.raises(ValueError):
        shell.build_argv("dir", "cmd")


@posix_only
def test_background_job_lifecycle(tmp_path):
    jobs = shell.JobManager(tmp_path)
    job = jobs.start("echo one; sleep 0.2; echo two")
    jobs.wait(job, 10)
    info = jobs.describe(job)
    assert info["status"] == "exited" and info["exit_code"] == 0
    assert info["output_tail"] == "one\ntwo\n"

    long = jobs.start("sleep 30")
    assert jobs.describe(long)["status"] == "running"
    jobs.stop(long)
    assert jobs.describe(long)["status"] == "stopped"
    with pytest.raises(ValueError):
        jobs.get("job999")


def test_clixml_error_stream_is_decoded():
    raw = (
        '#< CLIXML\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'
        '<S S="Error">Get-Thing : Invalid query _x000D__x000A_</S><S S="Error">At line:2 char:1 &amp; more_x000D__x000A_</S></Objs>'
    )
    assert shell.decode_clixml("before\n" + raw) == "before\nGet-Thing : Invalid query \nAt line:2 char:1 & more\n"
    assert shell.decode_clixml("plain text") == "plain text"
