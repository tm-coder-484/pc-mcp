import pytest

from pc_mcp import tunnel

LOG = """2026-09-24T22:30:44Z INF Requesting new quick Tunnel on trycloudflare.com...
2026-09-24T22:30:48Z INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
2026-09-24T22:30:48Z INF |  https://john-gym-hand-returning.trycloudflare.com                                         |
"""


def test_url_regex_finds_quick_tunnel_url():
    assert tunnel.URL_RE.findall(LOG) == ["https://john-gym-hand-returning.trycloudflare.com"]


@pytest.mark.parametrize(
    "plat,machine,asset",
    [
        ("win32", "AMD64", "cloudflared-windows-amd64.exe"),
        ("win32", "ARM64", "cloudflared-windows-amd64.exe"),
        ("darwin", "arm64", "cloudflared-darwin-arm64.tgz"),
        ("darwin", "x86_64", "cloudflared-darwin-amd64.tgz"),
        ("linux", "x86_64", "cloudflared-linux-amd64"),
        ("linux", "aarch64", "cloudflared-linux-arm64"),
        ("linux", "armv7l", "cloudflared-linux-arm"),
    ],
)
def test_asset_names(monkeypatch, plat, machine, asset):
    monkeypatch.setattr(tunnel.sys, "platform", plat)
    monkeypatch.setattr(tunnel.platform, "machine", lambda: machine)
    assert tunnel._asset_name() == asset
