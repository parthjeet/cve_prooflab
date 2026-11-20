import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "proof_pytest.py"

CASES = {
    "pass": ("def test_x():\n    pass\n", 10),
    "fail": ("def test_x():\n    assert False\n", 11),
    "skip_call": ("import pytest\n\ndef test_x():\n    pytest.skip('no')\n", 3),
    "skip_module": ("import pytest\n\npytestmark = pytest.mark.skip\n\ndef test_x():\n    pass\n", 3),
    "xfail": ("import pytest\n\n@pytest.mark.xfail\ndef test_x():\n    assert False\n", 3),
    "xpass": ("import pytest\n\n@pytest.mark.xfail\ndef test_x():\n    pass\n", 3),
    "pass_and_skip": (
        "import pytest\n\ndef test_a():\n    pass\n\ndef test_b():\n    pytest.skip('no')\n",
        3,
    ),
    "pass_and_fail": ("def test_a():\n    pass\n\ndef test_b():\n    assert False\n", 11),
    "no_tests": ("x = 1\n", 3),
    "syntax_error": ("def test_x(:\n", 3),
    "os_exit_0": ("import os\n\ndef test_x():\n    os._exit(0)\n", 0),
    "setup_error": (
        "import pytest\n\n@pytest.fixture\ndef f():\n    raise RuntimeError('boom')\n\ndef test_x(f):\n    pass\n",
        3,
    ),
    "teardown_error": (
        "import pytest\n\n@pytest.fixture\ndef f():\n    yield\n    raise RuntimeError('boom')\n\ndef test_x(f):\n    pass\n",
        3,
    ),
}


@pytest.mark.parametrize("name", CASES)
def test_exit_code(tmp_path, name):
    source, code = CASES[name]
    f = tmp_path / "test_proof_1.py"
    f.write_text(source)
    p = subprocess.run([sys.executable, str(SCRIPT), str(f)], capture_output=True, text=True)
    assert p.returncode == code, p.stdout + p.stderr


def test_no_arguments_exits_3():
    p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert p.returncode == 3
