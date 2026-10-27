import argparse
import gzip
import io
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGES = ("yubikit", "yubikey-manager")


def _locked_packages(path: Path) -> dict[tuple[str, str, str | None], str | None]:
    with path.open("rb") as lockfile:
        packages = tomllib.load(lockfile)["package"]
    return {
        (package["name"], package["version"], package.get("source")): package.get(
            "checksum"
        )
        for package in packages
    }


def normalize_sdist(archive: Path) -> None:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise FileNotFoundError("cargo is required to normalize source packages")
    with archive.open("rb") as archive_file:
        mtime = int.from_bytes(archive_file.read(8)[4:8], "little")

    with tempfile.TemporaryDirectory(dir=archive.parent) as temporary:
        directory = Path(temporary)
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            roots = {Path(member.name).parts[0] for member in members}
            if len(roots) != 1:
                raise ValueError(f"{archive} must contain exactly one root directory")
            source.extractall(directory / "source", filter="data")
            root = directory / "source" / roots.pop()
            lockfile = root / "Cargo.lock"
            original = _locked_packages(lockfile)

            # Maturin trims workspace members but copies the untrimmed lockfile.
            command = [cargo, "metadata", "--offline", "--format-version=1"]
            subprocess.run(  # noqa: S603
                command, cwd=root, stdout=subprocess.DEVNULL, check=True
            )
            for package, checksum in _locked_packages(lockfile).items():
                if package not in original or original[package] != checksum:
                    raise ValueError(
                        f"Normalizing {archive.name} changed a locked package's "
                        f"version, source or checksum: {package}"
                    )
            subprocess.run(  # noqa: S603
                [*command, "--locked"],
                cwd=root,
                stdout=subprocess.DEVNULL,
                check=True,
            )

            contents = lockfile.read_bytes()
            normalized = directory / archive.name
            with (
                normalized.open("wb") as output,
                gzip.GzipFile(
                    fileobj=output, filename="", mode="wb", mtime=mtime
                ) as compressed,
                tarfile.open(fileobj=compressed, mode="w") as destination,
            ):
                for member in members:
                    if member.name == f"{root.name}/Cargo.lock":
                        member.size = len(contents)
                        destination.addfile(member, io.BytesIO(contents))
                    else:
                        destination.addfile(member, source.extractfile(member))
        normalized.replace(archive)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build Python source packages with offline-normalized Cargo locks."
    )
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    output = parser.parse_args().out_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    if uv is None:
        raise FileNotFoundError("uv is required to build source packages")
    cargo = shutil.which("cargo")
    if cargo is None:
        raise FileNotFoundError("cargo is required to build source packages")
    subprocess.run(  # noqa: S603
        [cargo, "metadata", "--locked", "--format-version=1"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        check=True,
    )

    for package in PACKAGES:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            subprocess.run(  # noqa: S603
                [
                    uv,
                    "build",
                    "--package",
                    package,
                    "--sdist",
                    "--out-dir",
                    str(directory),
                ],
                cwd=ROOT,
                check=True,
            )
            (archive,) = directory.glob("*.tar.gz")
            normalize_sdist(archive)
            target = output / archive.name
            shutil.copyfile(archive, target)
            print(f"Built locked source package: {target}", flush=True)


if __name__ == "__main__":
    main()
