# pc-mcp

An MCP server that is quick to set up on any PC and lets a Claude instance — such as **Claude Code in the
cloud** — run commands and use tools on that PC. It includes a built-in **"why is my PC slow?"** diagnosis.

```
 your PC                                              the cloud
┌──────────────────────────────┐   outbound HTTPS    ┌───────────────────────────┐
│ pc-mcp  ── 127.0.0.1:8765 ───┼── cloudflared ─────▶│ https://<random>.try-     │◀── Claude Code (web),
│ (MCP server + tools)         │   (no open ports,   │   cloudflare.com/<token>/ │    Claude Code CLI,
└──────────────────────────────┘    works behind NAT)└───────────────────────────┘    any MCP client
```

## Quick start (about 2 minutes)

1. **Get the files:** clone this repo, or on GitHub click **Code → Download ZIP** and unzip it.
2. **Start it** — nothing else to install; the launcher installs [uv](https://docs.astral.sh/uv/), which fetches
   Python and all dependencies on first run:

   | OS | How |
   |---|---|
   | **Windows** | Double-click **`start-windows.bat`**. If Windows warns about a downloaded file: *More info → Run anyway*. |
   | **macOS** | Double-click **`start-mac.command`**. If macOS blocks it, run `./start.sh` in Terminal from the folder. |
   | **Linux** | `./start.sh` |

   Pick an access level when asked (full / ask-before-every-action / read-only).
3. **Connect Claude:** the window prints a box like this (the paste line is also copied to your clipboard):

   ```
   Connection URL (keep it private - anyone with it can control this PC):
     https://blue-river-cat.trycloudflare.com/Xy3...token.../mcp

   > Claude Code on the web / in the cloud - paste this into the chat:
     Connect to my PC with pc-mcp. Run: curl -fsSL https://.../pc.py -o /tmp/pc.py && python3 /tmp/pc.py connect https://.../mcp
   ```

   * **Claude Code on the web / cloud:** paste that line into the chat, then ask things like
     *"my PC is really slow, figure out why"*. Claude downloads a tiny client from your PC and uses it.
   * **Claude Code CLI:** `claude mcp add --transport http my-pc <connection URL>` — the tools then appear
     natively (`/mcp` shows them).
   * **Other MCP clients** that accept a server URL: give them the connection URL.

4. **Stop:** press **Ctrl+C** or close the window. The URL dies with it; every start gets a new URL and token.

Everything Claude does shows up live in the pc-mcp window and is written to `audit.log`
(`%LOCALAPPDATA%\pc-mcp\` on Windows, `~/.pc-mcp/` elsewhere).

## Tools

| Tool | What it does | Read-only mode |
|---|---|---|
| `diagnose_performance` | Samples CPU/RAM/disk/network per process, checks OS evidence, returns ranked findings with fixes | ✅ |
| `system_info` | OS, hardware, RAM, disks, uptime, battery, default shell | ✅ |
| `list_processes` | Processes by CPU / memory / disk I/O with command lines | ✅ |
| `find_space_hogs` | Biggest folders and files on a drive | ✅ |
| `list_directory`, `read_file` | Browse folders, read logs/configs | ✅ |
| `run_command` | PowerShell (Windows) / bash (macOS, Linux) / cmd; `background=true` for long jobs | — |
| `check_job`, `stop_job`, `list_jobs` | Follow long-running background commands | — |
| `kill_process` | End a process (core OS processes are refused) | — |
| `write_file` | Create / overwrite / append files | — |
| `take_screenshot` | Let Claude see the screen | — |

There is also an MCP prompt, `diagnose_slow_pc`, for clients that expose prompts.

### What `diagnose_performance` checks

* **CPU:** total load, per-app usage (grouped, e.g. `chrome x34`), runaway single-core processes, known
  culprits (Defender scans, Search indexing, Windows Update, OneDrive/Dropbox sync, Spotlight, Teams…),
  interrupt/DPC time (driver problems), iowait, VM steal, Linux pressure-stall info.
* **Throttling / power:** real CPU speed vs. rated (Windows perf counters), power plan and Windows 11 power
  mode, macOS thermal speed limit and Low Power Mode, battery, temperatures, CPU governor.
* **Memory:** RAM pressure and the apps using it, page-file/swap use, Windows commit charge, low-memory events,
  OOM kills, macOS memory pressure, "not enough RAM for this workload".
* **Disk:** free space (system drive weighted), busy %, response time, which process is hammering the disk,
  HDD vs SSD system drive, drive health, storage errors in the event log.
* **Everything else:** startup apps (respecting ones you disabled in Task Manager), slow-boot culprits, boot
  time, uptime & pending restarts (incl. the Windows Fast Startup gotcha), multiple antivirus products,
  hardware (WHEA) errors, unexpected shutdowns, apps that keep hanging/crashing, heavy network traffic.

Every section is best-effort: missing permissions just add a note under `collection_errors`. Running the
launcher **as Administrator** on Windows unlocks the boot-time and thermal checks.

## Security model — read this

* **The connection URL is the password.** It contains a random 192-bit token; requests without it get `401`.
  A new token and URL are generated on every start (pass `--token` to fix one). Don't post the URL publicly.
* The server listens on `127.0.0.1` only. The public URL exists only while the window is open.
* **Full mode means Claude can do anything your user account can.** If that's more than you want, use
  `--confirm` (you approve each command / file write / kill / screenshot in the pc-mcp window; unanswered
  requests auto-deny after 2 minutes) or `--mode read-only`.
* Claude is instructed to investigate read-only first and ask you before deleting files, killing important
  programs, uninstalling software or changing settings — but `--confirm` is the enforcement.
* The tunnel is a free Cloudflare "quick tunnel" (no account). Traffic is HTTPS to Cloudflare's edge.

## Command-line options

```
pc-mcp [--mode full|read-only] [--confirm] [--no-tunnel] [--host 127.0.0.1] [--port 8765]
       [--token TOKEN] [--stdio]
```

* `--no-tunnel` — local/LAN only (e.g. over Tailscale: `--no-tunnel --host 0.0.0.0`).
* `--stdio` — speak MCP over stdin/stdout for a **local** Claude Desktop / Claude Code, no network at all:
  `claude mcp add my-pc -- uv run --directory /path/to/pc-mcp pc-mcp --stdio`
* Environment variables: `PC_MCP_TOKEN`, `PC_MCP_PORT`, `PC_MCP_MODE`, `PC_MCP_CONFIRM=1`, `PC_MCP_HOME`.

Quick-tunnel URLs change on every start. If you want a fixed URL for a cloud environment's `.mcp.json`, run
your own named tunnel (Cloudflare account / Tailscale Funnel / ngrok) to `--no-tunnel` and use
[`examples/mcp.json`](examples/mcp.json) with a `PC_MCP_URL` environment variable.

## The client (`pc_mcp/pc_client.py`)

A standard-library-only script for agents that can run shell commands but can't hot-load an MCP server
mid-session. Each running pc-mcp serves it at `<base>/<token>/pc.py`.

```bash
python3 pc.py connect <connection URL>   # saves the URL, prints system info
python3 pc.py diagnose                   # summary + ranked findings (--json for everything)
python3 pc.py run "Get-Process | Sort-Object WS -Descending | Select-Object -First 10"
python3 pc.py run "sfc /scannow" --background && python3 pc.py job job1 --wait 60
python3 pc.py ps --sort memory          # also: hogs C:\Users, ls ~/Downloads, read <file>, screenshot --out s.jpg
python3 pc.py tools                      # every tool + parameters;  call <tool> key=value ...
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Banner says the tunnel connection isn't confirmed | Your network blocks cloudflared (outbound UDP/TCP 7844). Try another network, or use `--no-tunnel` with your own tunnel/VPN. |
| Claude gets `401` | It's using an old/incomplete URL — URLs change every start. Paste the new line. |
| Claude gets `530`/`502`/`1033` | pc-mcp was stopped or restarted. Start it and paste the new line. |
| A cloud session gets a proxy **403** for `*.trycloudflare.com` | The cloud environment's network policy blocks it: open the environment menu in the session's title bar → *Edit* → *Network access*, and allow `trycloudflare.com` (or a broader level). |
| Commands stop at ~90 s | Tunnelled requests are capped; use `background=true` / `pc.py run ... --background`. |
| macOS screenshot is black / fails | System Settings → Privacy & Security → Screen Recording → allow your terminal app. |

## Development

```bash
uv sync --group dev
uv run --group dev pytest        # 36 tests: auth, shell, diagnostics, tunnel, end-to-end server
uv run --group dev ruff check . && uv run --group dev ruff format --check .
uv run pc-mcp --no-tunnel        # run locally
```

`tests/windows_probe_mock.ps1` runs the Windows probe against mocked cmdlets, so the Windows logic is
tested on any OS with PowerShell 7 (`pwsh`).
