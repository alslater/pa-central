"""Tests for Settings.resolved_scan_task_fleet_url."""
import pytest

from app.core.config import settings as app_settings


class TestResolvedScanTaskFleetUrl:
    def test_explicit_value_wins_in_ecs_mode(self, monkeypatch):
        monkeypatch.setattr(app_settings, "local_docker_scan", False)
        monkeypatch.setattr(app_settings, "scan_task_fleet_url", "https://pa-central.example.com")
        assert app_settings.resolved_scan_task_fleet_url == "https://pa-central.example.com"

    def test_explicit_value_wins_in_local_docker_mode(self, monkeypatch):
        monkeypatch.setattr(app_settings, "local_docker_scan", True)
        monkeypatch.setattr(app_settings, "scan_task_fleet_url", "http://172.17.0.1:8000")
        assert app_settings.resolved_scan_task_fleet_url == "http://172.17.0.1:8000"

    def test_local_docker_mode_defaults_to_docker_gateway(self, monkeypatch):
        monkeypatch.setattr(app_settings, "local_docker_scan", True)
        monkeypatch.setattr(app_settings, "scan_task_fleet_url", None)
        assert app_settings.resolved_scan_task_fleet_url == "http://host.docker.internal:8000"

    def test_ecs_mode_with_no_url_raises(self, monkeypatch):
        """An ECS task shares no network with this server, so there is no
        default that could ever be correct — silently falling back to
        localhost would let the task launch and then silently fail to
        report results, instead of failing clearly at launch time."""
        monkeypatch.setattr(app_settings, "local_docker_scan", False)
        monkeypatch.setattr(app_settings, "scan_task_fleet_url", None)
        with pytest.raises(RuntimeError, match="SCAN_TASK_FLEET_URL"):
            _ = app_settings.resolved_scan_task_fleet_url
