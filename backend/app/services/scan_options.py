from __future__ import annotations

from functools import lru_cache

import click

from app.schemas import ScanFlag, ScanOptions

_EXCLUDED_PARAMS = {"path", "format", "fmt", "details", "config"}

_ALL_KNOWN_EXCLUSIONS: list[list[str]] = [
    ["scan_installed", "requirements"],
    ["scan_installed", "prod_only"],
]


@lru_cache(maxsize=1)
def _cached_scan_options_json() -> str:
    import typer
    from packagealert.cli.app import app as pa_app

    click_group = typer.main.get_group(pa_app)
    scan_click_cmd = click_group.commands.get("scan-project")

    if scan_click_cmd is None:
        from importlib.metadata import version as pkg_version
        pa_version = pkg_version("package-alert")
        available = ", ".join(sorted(click_group.commands.keys()))
        raise RuntimeError(
            f"Could not locate 'scan-project' command in package-alert "
            f"v{pa_version}. Available commands: {available}"
        )

    flags: list[ScanFlag] = []
    for param in scan_click_cmd.params:
        if isinstance(param, click.Argument):
            continue
        name = param.name
        if name in _EXCLUDED_PARAMS:
            continue
        opts = [o for o in param.opts if o.startswith("--")]
        if not opts:
            continue
        # For boolean flags with paired forms (--foo/--no-foo), Click may place
        # them in any order in param.opts.  Pick the non-negated form explicitly.
        positive = [o for o in opts if not o.startswith("--no-")]
        cli_flag = positive[0] if positive else opts[0]
        help_text = getattr(param, "help", None) or ""
        # Only treat as a presence-only bool flag when Click's is_flag is set.
        # BoolParamType alone means --foo=true/--foo=false (takes an explicit value),
        # which must be sent as a str so --flag=value form is preserved.
        is_bool = bool(getattr(param, "is_flag", False))
        flag_type: str = "bool" if is_bool else "str"
        flags.append(ScanFlag(name=name or cli_flag.lstrip("-").replace("-", "_"), cli_flag=cli_flag, help=help_text, type=flag_type))

    discovered_names = {f.name for f in flags}
    exclusions = [
        pair for pair in _ALL_KNOWN_EXCLUSIONS
        if all(name in discovered_names for name in pair)
    ]

    return ScanOptions(flags=flags, exclusions=exclusions).model_dump_json()


def get_scan_options() -> ScanOptions:
    return ScanOptions.model_validate_json(_cached_scan_options_json())
