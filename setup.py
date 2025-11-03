import os
import subprocess
import sys
import shutil
import configparser
import hashlib


VENV_DIR = "venv"
KNOWLEDGE_DIR = "knowledge"


def find_python_310_or_311():
    """
    Dynamically locate Python 3.10 or 3.11 executable in PATH.
    Returns (path, version_string) if found, else (None, None).
    """
    candidates = []

    if sys.platform == "win32":
        python_exe = shutil.which("python")
        if python_exe:
            candidates.append(python_exe)
    else:
        # Try version-suffixed first
        for suffix in ["3.11", "3.10"]:
            exe = shutil.which(f"python{suffix}")
            if exe:
                candidates.append(exe)
        # Fallback: try 'python3' or 'python'
        for name in ["python3", "python"]:
            exe = shutil.which(name)
            if exe:
                candidates.append(exe)

    for candidate in candidates:
        try:
            version_output = subprocess.check_output(
                [candidate, "--version"],
                stderr=subprocess.STDOUT,
                text=True
            ).strip()
            if version_output.startswith("Python 3.10") or version_output.startswith("Python 3.11"):
                return candidate, version_output
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
            continue

    return None, None


def check_python_binary():
    """
    Ensure Python 3.10 or 3.11 is available.
    Returns the path to the valid Python executable.
    """
    python_path, version = find_python_310_or_311()
    if not python_path:
        print("Error: Python 3.10 or 3.11 not found in your system PATH.")
        print("")
        print("This project requires Python 3.10 or 3.11 due to spaCy 3.7.2 compatibility.")
        print("  - Download from: https://www.python.org/downloads/")
        print("")
        if sys.platform == "darwin":
            print("  macOS: Use the official .pkg installer (recommended)")
            print("         Or: `brew install python@3.11` (if you use Homebrew)")
        elif sys.platform.startswith("linux"):
            print("  Linux: `sudo apt install python3.11` (Ubuntu/Debian)")
            print("         Or download from python.org")
        elif sys.platform == "win32":
            print("  Windows: Run installer and check 'Add Python to PATH'")
            print("           Verify: python --version")
        else:
            print("  Install Python 3.10 or 3.11 from python.org")
        print("")
        print("Verify with:")
        print("  python3.11 --version   (macOS/Linux)")
        print("  python --version       (Windows)")
        sys.exit(1)

    print(f"Using {version} at {python_path}")
    return python_path


def create_virtual_env(force_recreate=False):
    """
    Create virtual environment using detected Python 3.10/3.11.
    """
    python_path = check_python_binary()

    if force_recreate and os.path.exists(VENV_DIR):
        print(f"Removing existing virtual environment in {VENV_DIR}...")
        shutil.rmtree(VENV_DIR, ignore_errors=True)

    if not os.path.exists(VENV_DIR):
        print(f"Creating virtual environment in {VENV_DIR}...")
        result = subprocess.run([python_path, "-m", "venv", VENV_DIR])
        if result.returncode != 0:
            print("Failed to create virtual environment.")
            sys.exit(1)
    else:
        print(f"Virtual environment already exists in {VENV_DIR}.")

    python_cmd = get_python_cmd()
    if not os.path.exists(python_cmd):
        print(f"Virtual environment Python not found at {python_cmd}. Recreating...")
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        subprocess.run([python_path, "-m", "venv", VENV_DIR], check=True)


def get_python_cmd():
    """
    Return path to Python executable inside the virtual environment.
    """
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    else:
        return os.path.join(VENV_DIR, "bin", "python3")


def install_requirements():
    """
    Install project dependencies into the virtual environment.
    """
    python_cmd = get_python_cmd()
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found in project root.")
        sys.exit(1)

    print("Installing dependencies...")
    print("  Step 1/3: Upgrading pip...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "pip", "install", "--upgrade", "pip", "--quiet"], check=True)
    print("complete")

    print("  Step 2/3: Installing requirements...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], check=True)
    print("complete")

    print("  Step 3/3: Downloading spaCy model...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "spacy", "download", "en_core_web_sm", "--quiet"], check=True)
    print("complete")


def download_cci_xml(python_cmd):
    """
    Download and extract CCI XML if not present.
    """
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    cci_file = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    cci_url = config.get('DEFAULT', 'cci_url',
                         fallback='https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip')

    if os.path.exists(cci_file):
        print(f"{cci_file} already exists.")
        return

    print("Downloading CCI XML...")
    subprocess.run([python_cmd, "-m", "pip", "install", "requests"], check=True)
    script = f"""
import requests, zipfile, os, sys
url = '{cci_url}'
try:
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open('U_CCI_List.zip', 'wb') as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)
    with zipfile.ZipFile('U_CCI_List.zip', 'r') as z:
        z.extract('U_CCI_List.xml')
    os.rename('U_CCI_List.xml', '{cci_file}')
    os.remove('U_CCI_List.zip')
    print('Downloaded and extracted U_CCI_List.xml')
except Exception as e:
    print(f'Error: {{e}}', file=sys.stderr)
    sys.exit(1)
"""
    subprocess.run([python_cmd, "-c", script], check=True)


def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def download_nist_attack_mapping(python_cmd):
    """
    Download NIST to ATT&CK mapping if missing or outdated.
    """
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    mapping_file = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_attack-14.1-enterprise_json.json")
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    mapping_url = config.get('DEFAULT', 'nist_800_53_attack_mapping_url',
                             fallback='https://center-for-threat-informed-defense.github.io/mappings-explorer/data/nist_800_53/attack-14.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-14.1-enterprise_json.json')

    should_download = True
    if os.path.exists(mapping_file):
        print(f"Checking if {os.path.basename(mapping_file)} is up-to-date...")
        try:
            remote_hash_script = f"""
import requests, hashlib
r = requests.get('{mapping_url}', stream=True)
r.raise_for_status()
print(hashlib.sha256(r.content).hexdigest())
"""
            result = subprocess.run([python_cmd, "-c", remote_hash_script], capture_output=True, text=True, check=True)
            remote_hash = result.stdout.strip()
            local_hash = get_file_hash(mapping_file)
            if local_hash == remote_hash:
                print(f"{os.path.basename(mapping_file)} is up-to-date.")
                should_download = False
        except Exception as e:
            print(f"Update check failed ({e}). Will download fresh copy.")

    if should_download:
        print("Downloading NIST 800-53 to ATT&CK mapping...")
        download_script = f"""
import requests, os
url = '{mapping_url}'
r = requests.get(url, stream=True)
r.raise_for_status()
with open('{mapping_file}', 'wb') as f:
    for chunk in r.iter_content(8192):
        f.write(chunk)
print('Downloaded to {mapping_file}')
"""
        subprocess.run([python_cmd, "-c", download_script], check=True)


def run_demo(selected_model):
    """
    Launch the main application.
    """
    python_cmd = get_python_cmd()
    print(f"\nStarting NIST Compliance RAG Demo (model: {selected_model})")
    subprocess.run([python_cmd, "-m", "src.main", "--model", selected_model], check=True)


def main():
    # Model selection
    models = [
        ("all-MiniLM-L12-v2", "Fast, lightweight (12 layers)."),
        ("all-mpnet-base-v2", "Balanced performance and speed (default)."),
        ("multi-qa-MiniLM-L6-cos-v1", "Optimized for QA (6 layers)."),
        ("all-distilroberta-v1", "Distilled RoBERTa, good accuracy."),
        ("paraphrase-MiniLM-L6-v2", "Lightweight, excels at paraphrasing."),
        ("all-roberta-large-v1", "High accuracy, memory-intensive.")
    ]

    print("Select a SentenceTransformer model:")
    for i, (name, desc) in enumerate(models, 1):
        print(f"  {i}: {name} - {desc}")
    while True:
        try:
            choice = int(input("\nEnter number (1-6): "))
            if 1 <= choice <= len(models):
                break
            print(f"Please enter 1–{len(models)}.")
        except ValueError:
            print("Please enter a number.")
    selected_model = models[choice - 1][0]
    print(f"Selected: {selected_model}\n")

    # Setup
    create_virtual_env(force_recreate=False)
    install_requirements()

    python_cmd = get_python_cmd()
    download_cci_xml(python_cmd)
    download_nist_attack_mapping(python_cmd)

    # Run
    run_demo(selected_model)


if __name__ == "__main__":
    main()
