from __future__ import annotations

import tomllib

from packagealert.config import AppConfig
from pydantic import ValidationError

from app.schemas import LintResult

_OVERLAY_IGNORED_TOP = {"api_key", "server_url"}
_OVERLAY_IGNORED_PLUGINS = {"pa-central", "pa_central", "enabled"}

# plugins is not in AppConfig.model_fields but is a known extension section;
# unknown keys within it are intentionally allowed (extra="allow" semantics).
_PLUGINS_SECTION = "plugins"


def lint_toml(toml_content: str) -> LintResult:
    errors: list[str] = []
    warnings: list[str] = []

    # Step 1: TOML syntax check
    try:
        data = tomllib.loads(toml_content)
    except tomllib.TOMLDecodeError as exc:
        return LintResult(valid=False, errors=[str(exc)], warnings=[])

    # Step 2: Overlay-ignored top-level keys
    for key in _OVERLAY_IGNORED_TOP:
        if key in data:
            warnings.append(
                f"'{key}' is stripped by the host agent before applying fleet overlays"
                " and will have no effect."
            )

    # Step 2b: Overlay-ignored plugins keys
    plugins = data.get(_PLUGINS_SECTION)
    if isinstance(plugins, dict):
        for key in _OVERLAY_IGNORED_PLUGINS:
            if key in plugins:
                label = f"plugins.{key}"
                warnings.append(
                    f"'{label}' is stripped by the host agent before applying fleet"
                    " overlays and will have no effect."
                )

    # Step 3: Top-level section allowlist
    known_top = set(AppConfig.model_fields.keys()) | {_PLUGINS_SECTION}
    for key in data:
        if key not in known_top and key not in _OVERLAY_IGNORED_TOP:
            warnings.append(
                f"Unknown top-level key '{key}' — will be ignored by package-alert."
            )

    # Step 4: Per-section key allowlist
    # Read the annotation directly — avoids instantiating defaults and works whether
    # the field uses .default or .default_factory.
    for section_name, field_info in AppConfig.model_fields.items():
        if section_name == _PLUGINS_SECTION:
            continue
        section_model = field_info.annotation
        if not hasattr(section_model, "model_fields"):
            continue
        section_data = data.get(section_name)
        if not isinstance(section_data, dict):
            continue
        known_sub = set(section_model.model_fields.keys())
        for key in section_data:
            # Skip nested dicts (sub-tables like cooldown, filesystem_backend) —
            # they appear as dict values, not unknown string keys on the parent model,
            # but we only want to warn about string-keyed unknowns.
            if key not in known_sub and not isinstance(section_data[key], dict):
                warnings.append(
                    f"Unknown key '{key}' in [{section_name}]"
                    " — will be ignored by package-alert."
                )

    # Step 5: Type/value validation via Pydantic
    # Strip keys that AppConfig doesn't know about to avoid spurious extra-field errors
    all_known_top = set(AppConfig.model_fields.keys()) | {_PLUGINS_SECTION}
    stripped = {k: v for k, v in data.items() if k in all_known_top}

    # Remap plugins.pa-central -> pa_central for Pydantic field name compatibility
    if isinstance(stripped.get(_PLUGINS_SECTION), dict):
        p = stripped[_PLUGINS_SECTION].copy()
        if "pa-central" in p:
            p["pa_central"] = p.pop("pa-central")
        stripped[_PLUGINS_SECTION] = p

    try:
        AppConfig.model_validate(stripped)
    except ValidationError as exc:
        for err in exc.errors():
            loc = " → ".join(str(x) for x in err["loc"])
            errors.append(f"{loc}: {err['msg']}")

    return LintResult(valid=len(errors) == 0, errors=errors, warnings=warnings)
