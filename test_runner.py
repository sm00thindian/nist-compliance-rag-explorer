#!/usr/bin/env python3
"""
Test runner script that ensures virtual environment is activated.
Run with: python test_runner.py
"""
import os
import sys
import subprocess
import shutil

# Check if we're in a virtual environment
def is_venv_active():
    """Check if a virtual environment is currently active."""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def get_venv_python():
    """Get the path to the virtual environment's Python executable."""
    venv_dir = "venv"
    if sys.platform == "win32":
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        python_exe = os.path.join(venv_dir, "bin", "python3")

    if os.path.exists(python_exe):
        return python_exe
    return None

def activate_venv_and_run_tests():
    """Activate virtual environment and run tests."""
    venv_python = get_venv_python()

    if not venv_python:
        print("❌ Virtual environment not found. Please run 'python setup.py' first.")
        sys.exit(1)

    print(f"✅ Using virtual environment: {venv_python}")

    # Run the embedding test
    print("\n🔧 Running embedding system test...")
    result = subprocess.run([venv_python, "test_embedding.py"], cwd=os.getcwd())

    if result.returncode == 0:
        print("✅ Embedding test passed!")
    else:
        print("❌ Embedding test failed!")
        return result.returncode

    # Run other tests
    print("\n🧪 Running additional tests...")
    test_files = [
        "test/test_control_id.py",
        "test/test_cci_id.py",
        "test/test_stig_id.py",
        "test/test_rag_response.py"
    ]

    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Running {test_file}...")
            result = subprocess.run([venv_python, test_file], cwd=os.getcwd())
            if result.returncode != 0:
                print(f"❌ {test_file} failed!")
                return result.returncode
            else:
                print(f"✅ {test_file} passed!")

    print("\n🎉 All tests passed!")
    return 0

def main():
    """Main function."""
    print("NIST Compliance RAG Explorer - Test Runner")
    print("=" * 50)

    if not is_venv_active():
        print("ℹ️  Virtual environment not active. Using project's venv...")
        return activate_venv_and_run_tests()
    else:
        print("✅ Virtual environment is active.")
        # Run tests directly with current Python
        return run_tests_with_current_python()

def run_tests_with_current_python():
    """Run tests with the currently active Python (assumed to be venv)."""
    print("\n🔧 Running embedding system test...")
    result = subprocess.run([sys.executable, "test_embedding.py"], cwd=os.getcwd())

    if result.returncode == 0:
        print("✅ Embedding test passed!")
    else:
        print("❌ Embedding test failed!")
        return result.returncode

    # Run other tests
    print("\n🧪 Running additional tests...")
    test_files = [
        "test/test_control_id.py",
        "test/test_cci_id.py",
        "test/test_stig_id.py",
        "test/test_rag_response.py"
    ]

    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Running {test_file}...")
            result = subprocess.run([sys.executable, test_file], cwd=os.getcwd())
            if result.returncode != 0:
                print(f"❌ {test_file} failed!")
                return result.returncode
            else:
                print(f"✅ {test_file} passed!")

    print("\n🎉 All tests passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())