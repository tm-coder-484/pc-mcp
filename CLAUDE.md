# pc-mcp — notes for Claude

## If the user gives you a pc-mcp connection

A message like `Connect to my PC with pc-mcp. Run: curl -fsSL https://<x>.trycloudflare.com/<token>/pc.py -o /tmp/pc.py && python3 /tmp/pc.py connect <url>`
means their PC is running this server. Run exactly that, then use `python3 /tmp/pc.py ...`
(`diagnose`, `run`, `ps`, `hogs`, `ls`, `read`, `screenshot`, `tools`, `call <tool> k=v`). In this repo the same
client is at `pc_mcp/pc_client.py`.

- Treat it as someone's personal computer: investigate read-only first, explain what you want to change, and get
  a yes before deleting files, killing non-obvious processes, uninstalling software or changing settings.
- Windows commands run in Windows PowerShell 5.1 by default (`--shell cmd` for cmd). Sync commands are capped at
  ~90 s through the tunnel; use `--background` + `job <id> --wait 60` for longer ones.
- `401` = wrong/old URL; `530`/`502` = pc-mcp stopped or restarted (the URL changes each start) — ask for the new line.
- A proxy `403` for `*.trycloudflare.com` means this cloud environment's network policy blocks it.

## Working on this repo

- `pc_mcp/server.py` tools · `diagnostics.py` + `windows_probe.ps1` diagnosis · `shell.py` commands/jobs ·
  `auth.py` token gate · `tunnel.py` cloudflared · `cli.py` entry point · `pc_client.py` stdlib-only client
  (must stay dependency-free and Python 3.8 compatible).
- Test: `uv run --group dev pytest`. Lint: `uv run --group dev ruff check . && uv run --group dev ruff format --check .`
- `windows_probe.ps1` must stay Windows PowerShell 5.1 compatible and keep every section inside `Invoke-Section`
  so one failure never loses the whole JSON. Test its logic with `tests/windows_probe_mock.ps1` (needs `pwsh`).
- `start-windows.bat` is stored with CRLF line endings on purpose (see `.gitattributes`).
