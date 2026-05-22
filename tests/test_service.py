"""Tests for service module — unit-file generation, daemon guards."""

import os
import sys

import pytest

from strobes_shell_agent import service as svc


def test_build_command_basic():
    cmd = svc._build_command({
        "url": "https://example.com",
        "api-key": "abc",
        "org-id": "o",
    })
    assert "connect" in cmd
    assert "--url" in cmd and "https://example.com" in cmd
    assert "--api-key" in cmd and "abc" in cmd


def test_build_command_quotes_spaces():
    cmd = svc._build_command({"name": "my shell"})
    assert '"my shell"' in cmd


def test_build_command_drops_none_and_empty():
    cmd = svc._build_command({"url": "u", "cwd": None, "name": ""})
    assert "--cwd" not in cmd
    assert "--name" not in cmd


def test_build_command_bool_flag():
    cmd = svc._build_command({"no-ssl-verify": True, "ssl-verify": False})
    assert "--no-ssl-verify" in cmd
    assert "--ssl-verify" not in cmd


def test_daemonize_refuses_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(RuntimeError):
        svc.daemonize(tmp_path / "pid", tmp_path / "log")


def test_install_launchd_refuses_off_mac(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RuntimeError):
        svc.install_launchd({"url": "u", "api-key": "k"})


def test_label_constant():
    # Stable label is part of our service registration contract; do not change
    # casually since existing installs rely on it for uninstall.
    assert svc.LABEL == "co.strobes.shell-agent"


@pytest.mark.skipif(sys.platform == "win32", reason="systemd path")
def test_install_systemd_writes_unit(monkeypatch, tmp_path):
    """Smoke-test the unit-file path by stubbing systemctl and HOME."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Point Path.home() at our fake home.
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    # Stub shutil.which so it sees a fake systemctl.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n")
    os.chmod(fake_bin / "systemctl", 0o755)
    monkeypatch.setenv("PATH", str(fake_bin) + ":" + os.environ.get("PATH", ""))

    path = svc.install_systemd({
        "url": "https://example.com",
        "api-key": "k",
        "org-id": "o",
        "bridge-id": "b",
    }, scope="user")

    unit = (home / ".config/systemd/user/co.strobes.shell-agent.service")
    assert unit.exists()
    body = unit.read_text()
    assert "ExecStart=" in body
    assert "Restart=always" in body
    assert "https://example.com" in body
    assert path == str(unit)
