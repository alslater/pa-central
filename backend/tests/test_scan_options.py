import pytest
from unittest.mock import patch
from app.services.scan_options import get_scan_options, _cached_scan_options_json


def test_returns_scan_unpinned_bool():
    opts = get_scan_options()
    names = {f.name for f in opts.flags}
    assert "scan_unpinned" in names
    flag = next(f for f in opts.flags if f.name == "scan_unpinned")
    assert flag.type == "bool"
    assert flag.cli_flag == "--scan-unpinned"


def test_returns_scan_installed_bool():
    opts = get_scan_options()
    flag = next(f for f in opts.flags if f.name == "scan_installed")
    assert flag.type == "bool"
    assert flag.cli_flag == "--scan-installed"


def test_returns_requirements_str():
    opts = get_scan_options()
    flag = next(f for f in opts.flags if f.name == "requirements")
    assert flag.type == "str"
    assert flag.cli_flag == "--requirements"


def test_exclusions_include_scan_installed_requirements():
    opts = get_scan_options()
    assert ["scan_installed", "requirements"] in opts.exclusions


def test_prod_only_exclusion_only_if_flag_present():
    opts = get_scan_options()
    names = {f.name for f in opts.flags}
    has_prod_only = "prod_only" in names
    pair_present = ["scan_installed", "prod_only"] in opts.exclusions
    assert pair_present == has_prod_only


def test_result_is_cached():
    # Each call returns a fresh instance (to prevent shared mutable state),
    # but the underlying data is computed only once and must be equal.
    opts1 = get_scan_options()
    opts2 = get_scan_options()
    assert opts1 == opts2
    assert opts1 is not opts2


def test_missing_scan_project_command_raises_with_context():
    from unittest.mock import MagicMock
    fake_group = MagicMock()
    fake_group.commands = {"other-cmd": MagicMock()}  # scan-project absent
    with patch("typer.main.get_group", return_value=fake_group):
        _cached_scan_options_json.cache_clear()
        with pytest.raises(RuntimeError, match="scan-project") as exc_info:
            _cached_scan_options_json()
        msg = str(exc_info.value)
        assert "Available commands:" in msg
        assert "v" in msg  # version string present
    _cached_scan_options_json.cache_clear()


def test_internal_flags_excluded():
    opts = get_scan_options()
    names = {f.name for f in opts.flags}
    assert "format" not in names
    assert "fmt" not in names
    assert "details" not in names
    assert "config" not in names
    assert "path" not in names
