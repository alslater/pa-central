

def test_app_config_importable():
    from packagealert.config import AppConfig
    from pydantic import BaseModel
    assert issubclass(AppConfig, BaseModel)


def test_scan_project_command_introspectable():
    from app.services.scan_options import get_scan_options
    opts = get_scan_options()
    names = {f.name for f in opts.flags}
    assert "scan_unpinned" in names
    assert "scan_installed" in names
