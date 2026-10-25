import pytest

from a2agw.consult import netguard
from a2agw.consult.netguard import UnsafeURL, check_url


def _dns(monkeypatch, *addrs):
    async def fake(host):
        return list(addrs)

    monkeypatch.setattr(netguard, "_resolve", fake)


async def test_rejects_http_for_public(monkeypatch):
    _dns(monkeypatch, "93.184.216.34")
    monkeypatch.delenv("A2AGW_DEV", raising=False)
    with pytest.raises(UnsafeURL, match="https"):
        await check_url("http://example.com/x", "public")


async def test_dev_allows_http(monkeypatch):
    _dns(monkeypatch, "93.184.216.34")
    monkeypatch.setenv("A2AGW_DEV", "1")
    await check_url("http://example.com/x", "public")


async def test_public_https_ok(monkeypatch):
    _dns(monkeypatch, "93.184.216.34", "2606:2800:220:1::1")
    await check_url("https://example.com/x", "partner")


async def test_rejects_private_ip_for_partner(monkeypatch):
    _dns(monkeypatch, "10.0.0.5")
    with pytest.raises(UnsafeURL) as ei:
        await check_url("https://p.example.com", "partner")
    assert "10.0.0.5" not in str(ei.value)


async def test_rejects_if_any_address_private(monkeypatch):
    _dns(monkeypatch, "93.184.216.34", "127.0.0.1")
    with pytest.raises(UnsafeURL):
        await check_url("https://p.example.com", "public")


@pytest.mark.parametrize(
    "ip",
    ["169.254.169.254", "fd00:ec2::254", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1"],
)
async def test_rejects_metadata_and_special_literals(ip):
    host = f"[{ip}]" if ":" in ip else ip
    with pytest.raises(UnsafeURL):
        await check_url(f"https://{host}/", "public")


async def test_rejects_metadata_ip(monkeypatch):
    _dns(monkeypatch, "169.254.169.254")
    with pytest.raises(UnsafeURL):
        await check_url("https://evil.example.com", "public")


async def test_rejects_ipv4_mapped_ipv6(monkeypatch):
    with pytest.raises(UnsafeURL):
        await check_url("https://[::ffff:10.0.0.5]/", "public")
    _dns(monkeypatch, "::ffff:169.254.169.254")
    with pytest.raises(UnsafeURL):
        await check_url("https://evil.example.com", "partner")


async def test_rejects_userinfo():
    for tier in ("internal", "partner", "public"):
        with pytest.raises(UnsafeURL, match="userinfo"):
            await check_url("https://user:pw@example.com/", tier)
    with pytest.raises(UnsafeURL, match="userinfo"):
        await check_url("https://user@example.com/", "public")


async def test_rejects_bad_scheme_and_empty_host():
    with pytest.raises(UnsafeURL):
        await check_url("ftp://example.com/", "internal")
    with pytest.raises(UnsafeURL):
        await check_url("https:///path", "public")


async def test_unresolvable_rejected_for_non_internal(monkeypatch):
    async def boom(host):
        raise OSError("nxdomain")

    monkeypatch.setattr(netguard, "_resolve", boom)
    with pytest.raises(UnsafeURL):
        await check_url("https://nope.invalid", "partner")
    await check_url("http://nope.invalid", "internal")


async def test_internal_allows_private_http():
    await check_url("http://10.0.0.5:8080/", "internal")
    await check_url("http://t", "internal")


async def test_safe_get_deadline_covers_dns(monkeypatch):
    import asyncio as _asyncio
    import time as _time

    async def slow(host):
        await _asyncio.sleep(5)
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", slow)
    t = _time.monotonic()
    with pytest.raises(netguard.FetchError, match="timed out"):
        await netguard.safe_get(
            "https://slow.example.com/x", "public", max_bytes=10, deadline_s=0.2
        )
    assert _time.monotonic() - t < 1.0
