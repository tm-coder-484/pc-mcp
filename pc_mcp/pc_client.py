#!/usr/bin/env python3
"""pc.py - tiny command-line client for a pc-mcp server. Standard library only (Python 3.8+).

Meant for agents such as Claude Code in the cloud, which can run shell commands but cannot hot-load a
new MCP server mid-session. The PC owner starts pc-mcp and pastes the connection URL; then:

    python3 pc.py connect https://<name>.trycloudflare.com/<token>/mcp   # saves the URL, prints system info
    python3 pc.py diagnose                     # why is it slow? ranked findings + fixes
    python3 pc.py run "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"
    python3 pc.py run "long task" --background ; python3 pc.py job job1 --wait 60
    python3 pc.py ps --sort memory             # processes
    python3 pc.py hogs "C:\\Users"              # what is filling the disk
    python3 pc.py screenshot --out screen.jpg  # look at the screen
    python3 pc.py tools                        # every tool and its parameters
    python3 pc.py call <tool> '{"arg": 1}'     # call any tool (or: call <tool> arg=1 other=x)
"""

from __future__ import annotations

import argparse
import base64
import itertools
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path(os.environ.get("PC_MCP_CLIENT_CONFIG", str(Path.home() / ".pc-mcp-client.json")))
PROTOCOL = "2025-06-18"
_ids = itertools.count(1)


class RemoteError(Exception):
    pass


def _post(url: str, payload: dict, timeout: float) -> dict | None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL,
            "User-Agent": "pc-mcp-client/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ctype = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:300]
        if e.code == 401:
            raise RemoteError(
                "401 unauthorized - the token in the URL is wrong. Use the exact URL pc-mcp printed."
            ) from None
        if e.code in (502, 530, 1033) or "cloudflare" in detail.lower():
            raise RemoteError(
                f"HTTP {e.code} from the tunnel - pc-mcp is not running on the PC any more, or it restarted and "
                "printed a new URL (quick-tunnel URLs change on every start)."
            ) from None
        raise RemoteError(f"HTTP {e.code}: {detail}") from None
    except urllib.error.URLError as e:
        raise RemoteError(f"cannot reach {url.split('/')[2]}: {e.reason}. Is pc-mcp still running on the PC?") from None
    if "id" not in payload:
        return None
    if "text/event-stream" in ctype:
        for block in raw.split("\n\n"):
            data = "\n".join(ln[5:].lstrip() for ln in block.splitlines() if ln.startswith("data:"))
            if not data:
                continue
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            if msg.get("id") == payload["id"]:
                return msg
        raise RemoteError("no response in event stream")
    return json.loads(raw) if raw.strip() else None


def rpc(url: str, method: str, params: dict | None = None, timeout: float = 180) -> dict:
    msg = _post(url, {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}}, timeout)
    if msg is None:
        raise RemoteError("empty response")
    if "error" in msg:
        raise RemoteError(f"{msg['error'].get('message')} ({msg['error'].get('code')})")
    return msg["result"]


def initialize(url: str) -> dict:
    res = rpc(
        url,
        "initialize",
        {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "pc-mcp-client", "version": "0.1"},
        },
        timeout=30,
    )
    _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, 30)
    return res


def call_tool(url: str, name: str, arguments: dict, timeout: float = 180) -> dict:
    return rpc(url, "tools/call", {"name": name, "arguments": arguments}, timeout)


# ---------------------------------------------------------------------------------------------------------------


def load_url(cli_url: str | None) -> str:
    url = cli_url or os.environ.get("PC_MCP_URL")
    if not url and CONFIG.exists():
        url = json.loads(CONFIG.read_text()).get("url")
    if not url:
        sys.exit("No PC connected. Run: python3 pc.py connect <URL printed by pc-mcp on the PC>")
    return url.rstrip("/")


def result_payload(res: dict):
    """Return the structured value of a tool result if there is one, else the joined text."""
    if res.get("structuredContent") is not None:
        sc = res["structuredContent"]
        return sc["result"] if isinstance(sc, dict) and set(sc) == {"result"} else sc
    texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
    joined = "\n".join(texts)
    try:
        return json.loads(joined)
    except ValueError:
        return joined


def show(value) -> None:
    if isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def check_error(res: dict) -> None:
    if res.get("isError"):
        texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
        sys.exit("Tool error: " + "\n".join(texts))


def show_run(r: dict) -> None:
    if "job_id" in r:
        show(r)
        return
    if r.get("stdout"):
        print(r["stdout"].rstrip("\n"))
    if r.get("stderr"):
        print("--- stderr ---")
        print(r["stderr"].rstrip("\n"))
    extra = " TIMED OUT" if r.get("timed_out") else ""
    print(f"--- exit code {r.get('exit_code')} in {r.get('duration_seconds')}s via {r.get('shell')}{extra} ---")
    if r.get("note"):
        print(r["note"])


def show_diagnosis(r: dict, full: bool) -> None:
    print(r.get("summary", ""))
    print()
    for f in r.get("findings", []):
        print(f"[{f['severity'].upper():8}] ({f['area']}) {f['title']}")
        if f.get("detail"):
            print(f"           {f['detail']}")
        if f.get("fix"):
            print(f"           fix: {f['fix']}")
    s = r.get("sample", {})
    print(
        f"\nCPU {s.get('cpu_percent')}% | RAM {r.get('memory', {}).get('used_percent')}% used | "
        f"{s.get('process_count')} processes | sampled {s.get('window_seconds')}s"
    )
    busy = [p for p in s.get("top_by_cpu", [])[:6] if p["cpu_percent_of_total"] >= 0.5]
    print("Top CPU:   " + (", ".join(f"{p['name']} {p['cpu_percent_of_total']}%" for p in busy) or "nothing notable"))
    print(
        "Top apps by RAM: "
        + ", ".join(
            f"{a['name']} {a['memory_mb'] / 1024:.1f}GB" + (f" x{a['instances']}" if a["instances"] > 1 else "")
            for a in s.get("top_apps_by_memory", [])[:6]
        )
    )
    if r.get("collection_errors"):
        print("Collection notes: " + "; ".join(r["collection_errors"]))
    if full:
        print("\n--- full report ---")
        show(r)
    else:
        print("\n(add --json for the complete measurements)")


def parse_kv(items: list[str]) -> dict:
    if len(items) == 1 and items[0].lstrip().startswith("{"):
        return json.loads(items[0])
    out = {}
    for it in items:
        k, sep, v = it.partition("=")
        if not sep:
            sys.exit(f"argument {it!r} must look like key=value (or pass one JSON object)")
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="pc.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", help="connection URL (default: saved by `connect`, or $PC_MCP_URL)")
    p.add_argument("--timeout", type=float, default=180, help="seconds to wait for a response")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("connect", help="save the connection URL and show system info")
    c.add_argument("connect_url")
    sub.add_parser("info", help="system overview")
    sub.add_parser("tools", help="list tools and parameters")
    c = sub.add_parser("call", help="call any tool")
    c.add_argument("tool")
    c.add_argument("args", nargs="*", help="one JSON object, or key=value pairs")
    c = sub.add_parser("run", help="run a shell command on the PC")
    c.add_argument("command")
    c.add_argument("--shell", default="auto")
    c.add_argument("--cwd")
    c.add_argument("--cmd-timeout", type=int, default=60, dest="cmd_timeout")
    c.add_argument("--background", action="store_true")
    c = sub.add_parser("job", help="status/output of a background job")
    c.add_argument("job_id")
    c.add_argument("--wait", type=int, default=0)
    c.add_argument("--stop", action="store_true")
    c = sub.add_parser("diagnose", help="diagnose slowness")
    c.add_argument("--seconds", type=int, default=5)
    c.add_argument("--json", action="store_true", help="print the full report too")
    c = sub.add_parser("ps", help="list processes")
    c.add_argument("--sort", default="cpu", choices=["cpu", "memory", "disk", "name", "pid"])
    c.add_argument("--limit", type=int, default=20)
    c.add_argument("--filter")
    c = sub.add_parser("hogs", help="what is using disk space")
    c.add_argument("path", nargs="?")
    c = sub.add_parser("ls", help="list a directory")
    c.add_argument("path", nargs="?", default="~")
    c = sub.add_parser("read", help="read a text file")
    c.add_argument("path")
    c = sub.add_parser("screenshot", help="save a screenshot of the PC's screen")
    c.add_argument("--out", default="pc-screenshot.jpg")
    args = p.parse_args(argv)

    try:
        if args.cmd == "connect":
            url = args.connect_url.strip().rstrip("/")
            if not url.endswith("/mcp"):
                url += "/mcp"
            init = initialize(url)
            CONFIG.write_text(json.dumps({"url": url}))
            try:
                CONFIG.chmod(0o600)
            except OSError:
                pass
            print(
                f"Connected to {init.get('serverInfo', {}).get('title') or init.get('serverInfo', {}).get('name')} "
                f"(protocol {init.get('protocolVersion')}). URL saved to {CONFIG}.\n"
            )
            if init.get("instructions"):
                print(init["instructions"])
            res = call_tool(url, "system_info", {}, args.timeout)
            check_error(res)
            show(result_payload(res))
            return

        url = load_url(args.url)
        if args.cmd == "tools":
            for t in rpc(url, "tools/list", timeout=args.timeout)["tools"]:
                props = t.get("inputSchema", {}).get("properties", {})
                req = set(t.get("inputSchema", {}).get("required", []))
                params = ", ".join(
                    f"{k}{'' if k in req else '?'}: {v.get('type', v.get('anyOf', '?'))}" for k, v in props.items()
                )
                print(f"{t['name']}({params})")
                print("    " + (t.get("description") or "").strip().replace("\n", "\n    ") + "\n")
            return

        if args.cmd == "call":
            res = call_tool(url, args.tool, parse_kv(args.args), args.timeout)
        elif args.cmd == "info":
            res = call_tool(url, "system_info", {}, args.timeout)
        elif args.cmd == "run":
            res = call_tool(
                url,
                "run_command",
                {
                    "command": args.command,
                    "shell": args.shell,
                    "cwd": args.cwd,
                    "timeout_seconds": args.cmd_timeout,
                    "background": args.background,
                },
                max(args.timeout, args.cmd_timeout + 30),
            )
            check_error(res)
            show_run(result_payload(res))
            return
        elif args.cmd == "job":
            tool = "stop_job" if args.stop else "check_job"
            params = {"job_id": args.job_id} if args.stop else {"job_id": args.job_id, "wait_seconds": args.wait}
            res = call_tool(url, tool, params, max(args.timeout, args.wait + 30))
        elif args.cmd == "diagnose":
            res = call_tool(url, "diagnose_performance", {"sample_seconds": args.seconds}, max(args.timeout, 240))
            check_error(res)
            show_diagnosis(result_payload(res), args.json)
            return
        elif args.cmd == "ps":
            res = call_tool(
                url,
                "list_processes",
                {"sort_by": args.sort, "limit": args.limit, "name_contains": args.filter},
                args.timeout,
            )
        elif args.cmd == "hogs":
            res = call_tool(url, "find_space_hogs", {"path": args.path} if args.path else {}, max(args.timeout, 120))
        elif args.cmd == "ls":
            res = call_tool(url, "list_directory", {"path": args.path}, args.timeout)
        elif args.cmd == "read":
            res = call_tool(url, "read_file", {"path": args.path}, args.timeout)
            check_error(res)
            print(result_payload(res).get("content", ""))
            return
        elif args.cmd == "screenshot":
            res = call_tool(url, "take_screenshot", {}, args.timeout)
            check_error(res)
            for c in res.get("content", []):
                if c.get("type") == "image":
                    Path(args.out).write_bytes(base64.b64decode(c["data"]))
                    print(f"Saved screenshot to {os.path.abspath(args.out)}")
                    return
            sys.exit("no image returned")
        else:
            p.error(f"unknown command {args.cmd}")
            return
        check_error(res)
        show(result_payload(res))
    except RemoteError as e:
        sys.exit(f"pc-mcp: {e}")


if __name__ == "__main__":
    main()
