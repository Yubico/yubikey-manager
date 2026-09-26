import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Path to the root directory
ROOT_DIR = Path(__file__).parent.parent
SPEC_FILE = ROOT_DIR / "ykman.spec"


def _get_entrypoint_code() -> str:
    """Extract Entrypoint function definition from ykman.spec."""
    spec_lines = SPEC_FILE.read_text().splitlines()
    start_idx = None
    end_idx = None

    for i, line in enumerate(spec_lines):
        if line.startswith("def Entrypoint("):
            start_idx = i
        elif start_idx is not None and line.startswith("block_cipher"):
            end_idx = i
            break

    assert start_idx is not None and end_idx is not None, (
        "Could not extract Entrypoint definition from ykman.spec"
    )
    return "\n".join(spec_lines[start_idx:end_idx])


def test_spec_version_extraction_and_info():
    """Test version regex parsing and version_info.txt formatting logic from ykman.spec."""
    init_path = ROOT_DIR / "ykman" / "__init__.py"
    version_file = init_path.read_text()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    assert version_match is not None, (
        "Could not extract __version__ from ykman/__init__.py"
    )
    version = version_match.group(1)
    assert version

    # Test version_tuple formatting with different version string examples
    test_cases = [
        ("5.9.3-dev.0", "(5, 9, 3, 0)"),
        ("5.0.0", "(5, 0, 0, 0)"),
        ("1.2.3.4", "(1, 2, 3, 4, 0)"),
    ]

    for v_str, expected_tuple in test_cases:
        v_tuple = "(" + v_str.split("-")[0].replace(".", ", ") + ", 0)"
        assert v_tuple == expected_tuple

    # Test template replacement logic
    template_path = ROOT_DIR / "version_info.txt.in"
    if template_path.exists():
        version_tuple = "(" + version.split("-")[0].replace(".", ", ") + ", 0)"
        template_text = template_path.read_text()
        formatted_text = template_text.replace("{VERSION}", version).replace(
            "{VERSION_TUPLE}", version_tuple
        )
        assert version in formatted_text
        assert version_tuple in formatted_text


def test_spec_entrypoint_function(tmp_path):
    """Test Entrypoint recipe logic defined within ykman.spec."""
    entrypoint_code = _get_entrypoint_code()

    workpath = str(tmp_path)
    mock_analysis = MagicMock()

    # Execute Entrypoint definition with mocked Analysis and workpath
    global_scope = {
        "workpath": workpath,
        "Analysis": mock_analysis,
        "os": os,
    }
    exec(entrypoint_code, global_scope)
    Entrypoint = global_scope["Entrypoint"]

    # Test calling Entrypoint
    mock_dist = MagicMock()
    mock_dist.read_text.side_effect = lambda name: (
        "pkg_a\npkg_b" if name == "top_level.txt" else None
    )

    mock_ep = MagicMock()
    mock_ep.dist.name = "yubikey-manager"
    mock_ep.module = "ykman._cli.__main__"
    mock_ep.attr = "main"

    with (
        patch("importlib.metadata.distribution", return_value=mock_dist),
        patch("importlib.metadata.entry_points", return_value=[mock_ep]),
    ):
        res = Entrypoint(
            "yubikey-manager",
            "console_scripts",
            "ykman",
            hiddenimports=["dep1"],
            scripts=["extra_script.py"],
        )

    # Verify Analysis was called
    mock_analysis.assert_called_once()
    script_path = os.path.join(workpath, "ykman-script.py")
    assert mock_analysis.call_args[0][0] == [script_path, "extra_script.py"]
    assert res == mock_analysis.return_value

    # Verify generated script content
    generated_script = Path(script_path).read_text()
    assert "import ykman._cli.__main__" in generated_script
    assert "ykman._cli.__main__.main()" in generated_script
    assert "import pkg_a" in generated_script
    assert "import pkg_b" in generated_script


def test_spec_entrypoint_defaults(tmp_path):
    """Test Entrypoint when hiddenimports, pathex, scripts are omitted from kwargs."""
    entrypoint_code = _get_entrypoint_code()

    workpath = str(tmp_path)
    mock_analysis = MagicMock()

    global_scope = {
        "workpath": workpath,
        "Analysis": mock_analysis,
        "os": os,
    }
    exec(entrypoint_code, global_scope)
    Entrypoint = global_scope["Entrypoint"]

    mock_ep = MagicMock()
    mock_ep.dist.name = "yubikey-manager"
    mock_ep.module = "ykman._cli.__main__"
    mock_ep.attr = "main"

    with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
        Entrypoint("yubikey-manager", "console_scripts", "ykman")

    mock_analysis.assert_called_once()
    script_path = os.path.join(workpath, "ykman-script.py")
    assert mock_analysis.call_args[0][0] == [script_path]


def test_spec_entrypoint_get_toplevel_empty(tmp_path):
    """Test Entrypoint get_toplevel when top_level.txt is absent/empty."""
    entrypoint_code = _get_entrypoint_code()

    workpath = str(tmp_path)
    mock_analysis = MagicMock()

    global_scope = {
        "workpath": workpath,
        "Analysis": mock_analysis,
        "os": os,
    }
    exec(entrypoint_code, global_scope)
    Entrypoint = global_scope["Entrypoint"]

    mock_dist = MagicMock()
    mock_dist.read_text.return_value = None  # No top_level.txt

    mock_ep = MagicMock()
    mock_ep.dist.name = "yubikey-manager"
    mock_ep.module = "ykman._cli.__main__"
    mock_ep.attr = "main"

    with (
        patch("importlib.metadata.distribution", return_value=mock_dist),
        patch("importlib.metadata.entry_points", return_value=[mock_ep]),
    ):
        Entrypoint(
            "yubikey-manager",
            "console_scripts",
            "ykman",
            hiddenimports=["dep1"],
        )

    script_path = os.path.join(workpath, "ykman-script.py")
    generated_script = Path(script_path).read_text()
    assert "import ykman._cli.__main__" in generated_script
    assert "ykman._cli.__main__.main()" in generated_script


def test_spec_execution_simulation(tmp_path):
    """Simulate execution of ykman.spec with PyInstaller objects mocked."""
    spec_text = SPEC_FILE.read_text()

    # Create mock PyInstaller globals
    mock_analysis = MagicMock()
    mock_pyz = MagicMock()
    mock_exe = MagicMock()
    mock_collect = MagicMock()

    workpath = str(tmp_path / "work")
    os.makedirs(workpath, exist_ok=True)

    spec_globals = {
        "__file__": str(SPEC_FILE),
        "workpath": workpath,
        "Analysis": mock_analysis,
        "PYZ": mock_pyz,
        "EXE": mock_exe,
        "COLLECT": mock_collect,
    }

    # Change CWD to ROOT_DIR while executing spec
    old_cwd = os.getcwd()
    try:
        os.chdir(ROOT_DIR)
        exec(spec_text, spec_globals)
    finally:
        os.chdir(old_cwd)

    mock_analysis.assert_called()
    mock_pyz.assert_called()
    mock_exe.assert_called()
    mock_collect.assert_called()

    # Confirm version_info.txt was unlinked at end of spec script
    assert not (ROOT_DIR / "version_info.txt").exists()


@pytest.mark.skipif(
    os.environ.get("SKIP_PYINSTALLER_TESTS") == "1",
    reason="Skipping PyInstaller build test as requested",
)
def test_pyinstaller_build_spec():
    """Test executing PyInstaller on ykman.spec and verifying the generated executable."""
    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC_FILE), "--noconfirm"]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    assert res.returncode == 0, (
        f"PyInstaller build failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    )

    # Verify version_info.txt was unlinked by spec file
    assert not (ROOT_DIR / "version_info.txt").exists()

    # Determine executable name
    exe_name = "ykman.exe" if sys.platform == "win32" else "ykman"
    exe_path = ROOT_DIR / "dist" / "ykman" / exe_name
    assert exe_path.exists(), f"Executable not found at {exe_path}"

    # Run the built executable
    res_ver = subprocess.run(
        [str(exe_path), "--version"], capture_output=True, text=True
    )
    assert res_ver.returncode == 0
    assert "YubiKey Manager (ykman) version:" in res_ver.stdout

    res_help = subprocess.run([str(exe_path), "--help"], capture_output=True, text=True)
    assert res_help.returncode == 0
    assert "Configure your YubiKey via the command line" in res_help.stdout
