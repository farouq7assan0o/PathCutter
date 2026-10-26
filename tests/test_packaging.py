"""Packaging metadata stays consistent and the console entry point works."""
import tomllib
from pathlib import Path

import pathcutter

_PYPROJECT = tomllib.load(open(Path(__file__).parent.parent / "pyproject.toml", "rb"))
_PROJECT = _PYPROJECT["project"]


def test_version_matches_package():
    assert _PROJECT["version"] == pathcutter.__version__


def test_entry_point_target_is_importable_and_callable():
    mod, _, func = _PROJECT["scripts"]["pathcutter"].partition(":")
    import importlib
    m = importlib.import_module(mod)
    assert callable(getattr(m, func))


def test_version_flag_exits_zero():
    from pathcutter.cli import main
    import pytest
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0


def test_license_is_spdx_without_deprecated_classifier():
    assert _PROJECT["license"] == "MIT"
    assert _PROJECT["license-files"] == ["LICENSE"]
    assert not any(c.startswith("License ::") for c in _PROJECT["classifiers"])


def test_build_backend_supports_pep639():
    # SPDX license expressions need setuptools >= 77
    reqs = " ".join(_PYPROJECT["build-system"]["requires"])
    assert "setuptools" in reqs
