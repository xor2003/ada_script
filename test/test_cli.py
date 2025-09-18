# test/test_cli.py
import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Assuming CLI entrypoint in ada.py; use subprocess for testing
import subprocess

def test_cli_help():
    # Use direct path to ada.py instead of -m ada (avoids module issues)
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    # Check stderr for 'usage' since argparse may output to stderr in some envs
    output = result.stdout + result.stderr
    assert 'usage' in output.lower()

def test_cli_version():
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, '--version'], capture_output=True, text=True)
    assert result.returncode == 0
    output = result.stdout + result.stderr
    assert '0.1.0' in output  # Matches version in ada.py

def test_cli_basic_run():
    # Test basic run with missing files (should error gracefully)
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, 'nonexistent.exe'], capture_output=True, text=True)
    assert result.returncode == 1  # Expected error exit
    assert 'Error parsing MZ' in (result.stdout + result.stderr)

def test_cli_idc_failure():
    """Test that IDC parsing failure exits with non-zero code."""
    with tempfile.NamedTemporaryFile(suffix='.idc', delete=False) as f:
        f.write(b'invalid syntax here;')  # Causes Lark parse error
        invalid_idc = f.name

    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    try:
        result = subprocess.run(
            [sys.executable, ada_path, 'dummy.exe', '-s', invalid_idc],
            capture_output=True, text=True
        )
        assert result.returncode == 1, f"Expected exit 1, got {result.returncode}"
        output = result.stdout + result.stderr
        assert 'IDC' in output, "Should mention IDC error"
    finally:
        os.unlink(invalid_idc)