"""Command-line entry point: `pc-mcp` (or `python -m pc_mcp`)."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from pc_mcp import __version__
from pc_mcp.tunnel import QuickTunnel, default_home

CLIENT_FILE = Path(__file__).with_name("pc_client.py")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="pc-mcp",
        description="Let a remote Claude run commands, use tools and diagnose problems on this PC over MCP.",
    )
    p.add_argument(
        "--mode",
        choices=["full", "read-only"],
        default=os.environ.get("PC_MCP_MODE", "full"),
        help="full (default): commands, files, processes, screenshots. read-only: inspection/diagnosis only.",
    )
    p.add_argument(
        "--confirm",
        action="store_true",
        default=os.environ.get("PC_MCP_CONFIRM") == "1",
        help="ask at this PC's console before every command, file write, kill or screenshot",
    )
    p.add_argument("--no-tunnel", action="store_true", help="don't create a public URL (local/LAN use only)")
    p.add_argument("--host", default="127.0.0.1", help="interface to listen on (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=int(os.environ.get("PC_MCP_PORT", "8765")))
    p.add_argument(
        "--token", default=os.environ.get("PC_MCP_TOKEN"), help="access token (default: a new random one every start)"
    )
    p.add_argument("--stdio", action="store_true", help="speak MCP over stdin/stdout (for a local Claude Desktop/Code)")
    p.add_argument("--version", action="version", version=f"pc-mcp {__version__}")
    return p.parse_args(argv)


def _free_port(host: str, preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free TCP port")


def _copy_to_clipboard(text: str) -> bool:
    candidates = (
        [["clip"]]
        if sys.platform == "win32"
        else [["pbcopy"]]
        if sys.platform == "darwin"
        else [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    )
    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), timeout=5, check=True, capture_output=True)
                return True
            except (OSError, subprocess.SubprocessError):
                continue
    return False


def _banner(
    base: str, token: str, cfg_mode: str, confirm: bool, host: str, public: bool, home: Path
) -> tuple[str, str]:
    """Return (banner text, the one line worth putting on the clipboard)."""
    mcp_url = f"{base}/{token}/mcp"
    client_url = f"{base}/{token}/pc.py"
    paste = (
        f"Connect to my PC with pc-mcp. Run: curl -fsSL {client_url} -o /tmp/pc.py && "
        f"python3 /tmp/pc.py connect {mcp_url}"
    )
    mode = cfg_mode + (" + confirm each action" if confirm else "")
    lines = [
        "",
        "=" * 78,
        f"  pc-mcp {__version__} is running on {host}   [mode: {mode}]",
        "=" * 78,
        "",
        "  Connection URL (keep it private - anyone with it can control this PC):",
        f"    {mcp_url}",
        "",
    ]
    if public:
        lines += [
            "  > Claude Code on the web / in the cloud - paste this into the chat:",
            f"    {paste}",
            "",
        ]
    lines += [
        "  > Claude Code CLI:",
        f"    claude mcp add --transport http my-pc {mcp_url}",
        "",
        "  > Any other MCP client that takes a URL: use the connection URL above.",
        "",
        f"  Saved to {home / 'connection.txt'}",
        "  Everything Claude does is shown below and logged to audit.log.",
        "  Press Ctrl+C (or close this window) to stop and disconnect.",
        "=" * 78,
        "",
    ]
    return "\n".join(lines), paste if public else mcp_url


def _raise_interrupt(signum, frame) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):  # window closed / killed: still run the cleanup below
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _raise_interrupt)
    home = default_home()
    home.mkdir(parents=True, exist_ok=True)

    from pc_mcp.server import Config, build_server

    if args.stdio:
        cfg = Config(mode=args.mode, confirm=False, home=home, max_sync_timeout=600, quiet=True)
        mcp, jobs, _ = build_server(cfg)
        try:
            mcp.run("stdio")
        finally:
            jobs.stop_all()
        return

    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    from pc_mcp.auth import TokenGate

    token = args.token or secrets.token_urlsafe(24)
    use_tunnel = not args.no_tunnel
    cfg = Config(mode=args.mode, confirm=args.confirm, home=home, max_sync_timeout=90 if use_tunnel else 600)
    mcp, jobs, console = build_server(cfg)

    @mcp.custom_route("/pc.py", methods=["GET"])
    async def client_script(_: Request) -> PlainTextResponse:
        return PlainTextResponse(CLIENT_FILE.read_text(encoding="utf-8"))

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app = mcp.streamable_http_app(
        stateless_http=True,
        # The random token in every request is what keeps strangers (and DNS-rebinding pages) out; the
        # Host header will be the tunnel's hostname, so the SDK's localhost-only Host check must be off.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host=args.host,
    )
    port = _free_port(args.host, args.port)
    server = uvicorn.Server(
        uvicorn.Config(TokenGate(app, token), host=args.host, port=port, log_level="warning", access_log=False)
    )
    server_thread = threading.Thread(target=server.run, name="uvicorn", daemon=True)
    server_thread.start()
    while not server.started:
        if not server_thread.is_alive():
            sys.exit(f"pc-mcp: the HTTP server failed to start on {args.host}:{port}")
        time.sleep(0.05)

    local_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    local_base = f"http://{local_host}:{port}"
    tunnel: QuickTunnel | None = None

    def announce(base: str, public: bool) -> None:
        text, clip = _banner(base, token, cfg.mode, cfg.confirm, socket.gethostname(), public, home)
        print(text, flush=True)
        (home / "connection.txt").write_text(f"{base}/{token}/mcp\n\n{clip}\n", encoding="utf-8")
        if _copy_to_clipboard(clip):
            print("  (The line to paste has been copied to your clipboard.)\n", flush=True)

    def open_tunnel() -> QuickTunnel:
        print("  Opening a secure tunnel so Claude can reach this PC...", flush=True)
        t = QuickTunnel(local_base, home / "bin", home / "cloudflared.log", log=lambda m: print("  " + m, flush=True))
        t.start()
        return t

    try:
        if use_tunnel:
            try:
                tunnel = open_tunnel()
            except Exception as e:  # noqa: BLE001
                print(
                    f"\n  !! Could not open the tunnel: {e}\n"
                    "     Check your internet connection / firewall (cloudflared needs outbound UDP or TCP 7844),\n"
                    f"     or run with --no-tunnel for local use. Serving locally on {local_base} for now.\n",
                    flush=True,
                )
            if tunnel:
                announce(tunnel.public_url, public=True)
                if not tunnel.connected.is_set():
                    print(
                        "  !! The tunnel URL was issued but cloudflared has not confirmed a connection yet.\n"
                        "     If Claude cannot connect, your network may block cloudflared (outbound UDP/TCP 7844);\n"
                        f"     details in {home / 'cloudflared.log'}\n",
                        flush=True,
                    )
            else:
                announce(local_base, public=False)
        else:
            announce(local_base, public=False)

        while server_thread.is_alive():
            time.sleep(1)
            if tunnel and not tunnel.alive():
                console.event("tunnel dropped - reconnecting (the URL will change)")
                try:
                    tunnel = open_tunnel()
                    announce(tunnel.public_url, public=True)
                except Exception as e:  # noqa: BLE001
                    console.event(f"tunnel reconnect failed: {e}; retrying in 15s")
                    time.sleep(15)
    except KeyboardInterrupt:
        print("\n  Stopping pc-mcp...", flush=True)
    finally:
        if tunnel:
            tunnel.stop()
        jobs.stop_all()
        server.should_exit = True
        server_thread.join(timeout=5)
        print("  Stopped. The connection URL no longer works.", flush=True)


if __name__ == "__main__":
    main()
