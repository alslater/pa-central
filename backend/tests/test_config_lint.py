from app.services.config_lint import lint_toml


def test_valid_empty_toml():
    result = lint_toml("")
    assert result.valid is True
    assert result.errors == []
    assert result.warnings == []


def test_valid_known_sections():
    toml = """
[osv]
cache_ttl_hours = 48

[heuristics]
enabled = true
warning_threshold = 50
"""
    result = lint_toml(toml)
    assert result.valid is True
    assert result.errors == []
    assert result.warnings == []


def test_syntax_error():
    result = lint_toml("[bad toml")
    assert result.valid is False
    assert len(result.errors) == 1
    assert result.warnings == []


def test_syntax_error_includes_line_info():
    result = lint_toml("[bad toml")
    assert any(c.isdigit() for c in result.errors[0])


def test_unknown_top_level_key():
    result = lint_toml("bogus_section = true")
    assert result.valid is True
    assert result.errors == []
    assert any("bogus_section" in w for w in result.warnings)


def test_unknown_sub_key():
    result = lint_toml("[heuristics]\nbogus_key = 1")
    assert result.valid is True
    assert result.errors == []
    assert any("bogus_key" in w for w in result.warnings)


def test_plugins_extra_keys_no_warning():
    result = lint_toml('[plugins]\nsome_plugin_key = "value"')
    assert result.valid is True
    assert result.warnings == []


def test_wrong_type_error():
    result = lint_toml('[osv]\ncache_ttl_hours = "not-an-int"')
    assert result.valid is False
    assert len(result.errors) >= 1


def test_out_of_range_error():
    # top_packages_refresh_days has ge=1 in HeuristicsConfig
    result = lint_toml("[heuristics]\ntop_packages_refresh_days = 0")
    assert result.valid is False
    assert len(result.errors) >= 1


def test_overlay_ignored_api_key_warns():
    result = lint_toml('api_key = "secret"')
    assert result.valid is True
    assert any("api_key" in w for w in result.warnings)


def test_overlay_ignored_server_url_warns():
    result = lint_toml('server_url = "https://example.com"')
    assert result.valid is True
    assert any("server_url" in w for w in result.warnings)


def test_overlay_ignored_plugins_enabled_warns():
    result = lint_toml('[plugins]\nenabled = ["pa-central"]')
    assert result.valid is True
    assert any("plugins.enabled" in w for w in result.warnings)


def test_overlay_ignored_plugins_pa_central_warns():
    result = lint_toml('[plugins.pa-central]\napi_key = "x"')
    assert result.valid is True
    assert any("pa-central" in w for w in result.warnings)
