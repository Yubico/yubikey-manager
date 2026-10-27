import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from extract_signed_zip import extract_flat
from windows_signing import ARCHITECTURES, prepare, restore


class WindowsSigningTests(unittest.TestCase):
    def create_artifact(self, root, architecture, kind):
        arch = architecture["arch"]
        if kind == "binaries":
            artifact = root / f"ykman-builds-windows-{arch}"
            inputs = [
                artifact / "ykman/ykman.exe",
                artifact / "ykman/ykman-svc.exe",
                artifact / "ykman/plugin.dll",
            ]
        else:
            artifact = root / f"ykman-installer-windows{architecture['suffix']}"
            inputs = [artifact / f"ykman{architecture['suffix']}.msi"]
            binaries = artifact / "ykman"
            binaries.mkdir(parents=True)
            for name in ("ykman.exe", "ykman-svc.exe"):
                (binaries / name).write_bytes(b"signed executable")
        for path in inputs:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"{arch}:{path.name}".encode())
        scripts = artifact / "scripts"
        scripts.mkdir()
        (scripts / "make_msi.ps1").write_text("unchanged")
        (artifact / "ykman-service.msm").write_bytes(b"unchanged service module")
        return inputs

    def test_round_trip_both_and_either_architecture(self):
        for kind in ("binaries", "installers"):
            for architectures in (ARCHITECTURES, ARCHITECTURES[:1], ARCHITECTURES[1:]):
                with (
                    self.subTest(kind=kind, architectures=architectures),
                    TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    artifacts = root / "artifacts"
                    inputs = []
                    for architecture in architectures:
                        inputs.extend(
                            self.create_artifact(artifacts, architecture, kind)
                        )
                    original = {
                        path: path.read_bytes()
                        for path in artifacts.rglob("*")
                        if path.is_file()
                    }
                    staging = root / "signing-input"
                    script = Path(__file__).with_name("windows_signing.py")
                    output = subprocess.check_output(  # noqa: S603
                        [
                            sys.executable,
                            str(script),
                            "prepare",
                            kind,
                            str(artifacts),
                            str(staging),
                        ],
                        text=True,
                    )
                    outputs = dict(line.split("=", 1) for line in output.splitlines())
                    self.assertEqual(set(outputs), {"architectures"})
                    self.assertEqual(
                        json.loads(outputs["architectures"]),
                        [item["arch"] for item in architectures],
                    )
                    archive = root / "1.zip"
                    with ZipFile(archive, "w") as zip_file:
                        for path in (staging / "files").iterdir():
                            zip_file.writestr(
                                f"/scribe/signing-input/files/{path.name}",
                                b"signed:" + path.read_bytes(),
                            )
                    signed = root / "signed"
                    signed.mkdir()
                    extract_flat(archive, signed)
                    subprocess.run(  # noqa: S603
                        [
                            sys.executable,
                            str(script),
                            "restore",
                            str(artifacts),
                            str(staging),
                            str(signed),
                        ],
                        check=True,
                    )
                    for path, data in original.items():
                        self.assertEqual(
                            path.read_bytes(),
                            b"signed:" + data if path in inputs else data,
                        )

    def test_rejects_missing_artifacts(self):
        for kind in ("binaries", "installers"):
            with self.subTest(kind=kind), TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(ValueError, "No .* artifacts"):
                    prepare(kind, root / "missing", root / "staging")
                self.assertFalse((root / "staging").exists())

    def test_rejects_incomplete_artifact(self):
        for kind in ("binaries", "installers"):
            with self.subTest(kind=kind), TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = self.create_artifact(
                    root / "artifacts", ARCHITECTURES[0], kind
                )
                inputs[0].unlink()
                with self.assertRaisesRegex(ValueError, "Missing"):
                    prepare(kind, root / "artifacts", root / "staging")
                self.assertFalse((root / "staging").exists())

    def test_rejects_duplicate_names_within_architecture(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self.create_artifact(
                root / "artifacts", ARCHITECTURES[0], "binaries"
            )
            duplicate = inputs[0].parent / "nested/ykman.exe"
            duplicate.parent.mkdir()
            duplicate.write_bytes(b"duplicate")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                prepare("binaries", root / "artifacts", root / "staging")

    def test_rejects_missing_and_unexpected_signed_files_before_replacing(self):
        for mismatch in ("missing", "unexpected"):
            with self.subTest(mismatch=mismatch), TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = self.create_artifact(
                    root / "artifacts", ARCHITECTURES[0], "binaries"
                )
                original = {path: path.read_bytes() for path in inputs}
                prepare("binaries", root / "artifacts", root / "staging")
                signed = root / "signed"
                signed.mkdir()
                for path in (root / "staging/files").iterdir():
                    (signed / path.name).write_bytes(b"signed")
                if mismatch == "missing":
                    next(signed.iterdir()).unlink()
                else:
                    (signed / "unexpected.exe").write_bytes(b"unexpected")
                with self.assertRaisesRegex(ValueError, "do not match"):
                    restore(root / "artifacts", root / "staging", signed)
                self.assertEqual({path: path.read_bytes() for path in inputs}, original)


if __name__ == "__main__":
    unittest.main()
