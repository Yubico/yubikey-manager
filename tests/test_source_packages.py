import gzip
import io
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest
from build_source_packages import main, normalize_sdist


@pytest.fixture
def source_package(tmp_path):
    files = {
        "Cargo.toml": '[workspace]\nmembers = ["kept"]\nresolver = "2"\n',
        "Cargo.lock": (
            'version = 4\n\n[[package]]\nname = "kept"\nversion = "1.0.0"\n\n'
            '[[package]]\nname = "unused"\nversion = "1.0.0"\n'
        ),
        "kept/Cargo.toml": (
            '[package]\nname = "kept"\nversion = "1.0.0"\nedition = "2021"\n'
        ),
        "kept/src/lib.rs": "",
        "pyproject.toml": '[project]\nname = "example"\nversion = "1.0.0"\n',
    }
    archive = tmp_path / "example-1.0.0.tar.gz"
    with (
        archive.open("wb") as output,
        gzip.GzipFile(
            fileobj=output, filename="", mode="wb", mtime=1234567890
        ) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as package,
    ):
        for path, contents in files.items():
            member = tarfile.TarInfo(f"example-1.0.0/{path}")
            data = contents.encode()
            member.size = len(data)
            member.mtime = 1234567890
            package.addfile(member, io.BytesIO(data))
    return archive


def test_normalize_sdist_preserves_sources_and_pins(source_package):
    with tarfile.open(source_package) as package:
        before = {
            member.name: (package.extractfile(member).read(), member.mtime, member.mode)
            for member in package.getmembers()
        }

    normalize_sdist(source_package)

    with tarfile.open(source_package) as package:
        after = {
            member.name: (package.extractfile(member).read(), member.mtime, member.mode)
            for member in package.getmembers()
        }
    assert before.keys() == after.keys()
    for name, value in before.items():
        if not name.endswith("/Cargo.lock"):
            assert value == after[name]
    lock = tomllib.loads(after["example-1.0.0/Cargo.lock"][0].decode())
    assert lock["package"] == [{"name": "kept", "version": "1.0.0"}]
    assert int.from_bytes(source_package.read_bytes()[4:8], "little") == 1234567890

    normalized = source_package.read_bytes()
    normalize_sdist(source_package)
    assert source_package.read_bytes() == normalized


@pytest.mark.parametrize(
    "replacement",
    [
        'name = "kept"\nversion = "1.0.1"',
        'name = "kept"\nversion = "1.0.0"\nsource = "registry+https://example.invalid"',
        'name = "kept"\nversion = "1.0.0"\nchecksum = "changed"',
    ],
)
def test_normalize_sdist_rejects_dependency_changes(
    source_package, monkeypatch, replacement
):
    original = source_package.read_bytes()

    def change_dependency(command, *, cwd, **kwargs):
        assert "--offline" in command
        lockfile = Path(cwd) / "Cargo.lock"
        lockfile.write_text(
            lockfile.read_text().replace(
                'name = "kept"\nversion = "1.0.0"', replacement
            )
        )

    monkeypatch.setattr("build_source_packages.subprocess.run", change_dependency)
    with pytest.raises(ValueError, match="version, source or checksum"):
        normalize_sdist(source_package)
    assert source_package.read_bytes() == original


def test_normalize_sdist_surfaces_cargo_failures(source_package, monkeypatch):
    original = source_package.read_bytes()

    def fail_metadata(*args, **kwargs):
        raise RuntimeError("cargo metadata failed")

    monkeypatch.setattr("build_source_packages.subprocess.run", fail_metadata)
    with pytest.raises(RuntimeError, match="cargo metadata failed"):
        normalize_sdist(source_package)
    assert source_package.read_bytes() == original


def test_source_build_rejects_stale_workspace_lock(tmp_path, monkeypatch):
    output = tmp_path / "dist"
    monkeypatch.setattr(
        "sys.argv", ["build_source_packages.py", "--out-dir", str(output)]
    )
    monkeypatch.setattr("build_source_packages.shutil.which", lambda tool: f"/{tool}")

    def reject_lock(command, **kwargs):
        assert "--locked" in command
        raise subprocess.CalledProcessError(101, command)

    monkeypatch.setattr("build_source_packages.subprocess.run", reject_lock)
    with pytest.raises(subprocess.CalledProcessError):
        main()
    assert not list(output.iterdir())
