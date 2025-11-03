import os
import subprocess
import sys
import shutil
import configparser
import hashlib
import platform

VENV_DIR = "venv"
KNOWLEDGE_DIR = "knowledge"


def find_python_312():
    """
    Dynamically locate Python 3.12 executable in the system PATH.
    - Unix/macOS: Looks for 'python3.12' or 'python3' (if version is 3.12)
    - Windows: Looks for 'python.exe' and verifies version
    Returns full path to executable if found and version is 3.12.x, else None.
    """
    candidates = []

    if sys.platform == "win32":
        # On Windows, typically just 'python' (no version suffix)
        python_exe = shutil.which("python")
        if python_exe:
            candidates.append(python_exe)
    else:
        # Unix-like: Prefer version-suffixed
        python_312 = shutil.which("python3.12")
        if python_312:
            candidates.append(python_312)
        # Fallback: Check if 'python3' is actually 3.12
        python3 = shutil.which("python3")
        if python3:
            candidates.append(python3)

    for candidate in candidates:
        try:
            version_output = subprocess.check_output(
                [candidate, "--version"], 
                stderr=subprocess.STDOUT, 
                text=True
            ).strip()
            if version_output.startswith("Python 3.12"):
                return candidate
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
            continue

    return None


def check_python_binary():
    """
    Validate that Python 3.12 is available. If not, provide clear installation instructions.
    Returns the path to the Python 3.12 executable.
    """
    python_312_path = find_python_312()
    if not python_312_path:
        print("Error: Python 3.12 not found in your system PATH.")
        print("")
        print("Please install Python 3.12 and ensure it's accessible from the command line:")
        print("  - Download from: https://www.python.org/downloads/")
        print("")
        if sys.platform == "darwin":
            print("  macOS: Install via .pkg from python.org (recommended) or your package manager.")
            print("         After install, add to PATH or use full path.")
        elif sys.platform.startswith("linux"):
            print("  Linux: Use your package manager (e.g., 'sudo apt install python3.12' on Ubuntu)")
            print("         Or install from python.org.")
        elif sys.platform == "win32":
            print("  Windows: Run the installer and check 'Add Python to PATH'.")
            print("           Verify with: python --version")
        else:
            print("  Install Python 3.12 from https://www.python.org/downloads/ and add to PATH.")
        print("")
        print("After installation, verify with:")
        print("  python3.12 --version   (macOS/Linux)")
        print("  python --version       (Windows)")
        sys.exit(1)

    print(f"Using Python 3.12 at {python_312_path}")
    return python_312_path


def create_virtual_env(force_recreate=False):
    """
    Create a virtual environment using the detected Python 3.12.
    """
    python_312_path = check_python_binary()

    if force_recreate and os.path.exists(VENV_DIR):
        print(f"Removing existing virtual environment in {VENV_DIR}...")
        shutil.rmtree(VENV_DIR, ignore_errors=True)

    if not os.path.exists(VENV_DIR):
        print(f"Creating virtual environment in {VENV_DIR}...")
        result = subprocess.run([python_312_path, "-m", "venv", VENV_DIR])
        if result.returncode != 0:
            print("Failed to create virtual environment.")
            sys.exit(1)
    else:
        print(f"Virtual environment already exists in {VENV_DIR}.")

    # Verify venv Python exists
    python_cmd = get_python_cmd()
    if not os.path.exists(python_cmd):
        print(f"Virtual environment Python not found at {python_cmd}. Recreating...")
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        subprocess.run([python_312_path, "-m", "venv", VENV_DIR], check=True)


def get_python_cmd():
    """
    Return the path to the Python executable inside the virtual environment.
    """
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    else:
        return os.path.join(VENV_DIR, "bin", "python3")


def install_requirements():
    """
    Install dependencies from requirements.txt into the virtual environment.
    """
    python_cmd = get_python_cmd()
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found in project root.")
        sys.exit(1)

    print("Installing dependencies...")
    print("  Step 1/3: Upgrading pip...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "pip", "install", "--upgrade", "pip", "--quiet"], check=True)
    print("complete")

    print("  Step 2/3: Installing requirements from requirements.txt...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], check=True)
    print("complete")

    print("  Step 3/3: Downloading spaCy model...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "spacy", "download", "en_core_web_sm", "--quiet"], check=True)
    print("complete")


def download_cci_xml(python_cmd):
    """
    Download and extract CCI XML file if not already present.
    """
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    cci_file = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    cci_url = config.get('DEFAULT', 'cci_url', fallback='https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip')

    if os.path.exists(cci_file):
        print(f"{cci_file} already exists.")
        return

    print("Downloading CCI XML...")
    subprocess.run([python_cmd, "-m", "pip", "install", "requests"], check=True)
    subprocess.run([python_cmd, "-c", f"""
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
    print(f'Failed to download CCI XML: {{e}}', file=sys.stderr)
    sys.exit(1)
"""], check=True)


def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def download_nist_attack_mapping(python_cmd):
    """
    Download NIST 800-53 to MITRE ATT&CK mapping if not present or outdated.
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
            # Get remote hash
            remote_hash_script = f"""
import requests, hashlib, sys
r = requests.get('{mapping_url}', stream=True)
r.raise_for_status()
remote_hash = hashlib.sha256(r.content).hexdigest()
with open('remote_hash.txt', 'w') as f:
    f.write(remote_hash)
"""
            subprocess.run([python_cmd, "-c", remote_hash_script], check=True)
            with open("remote_hash.txt", "r") as f:
                remote_hash = f.read().strip()
            os.remove("remote_hash.txt")

            local_hash = get_file_hash(mapping_file)
            if local_hash == remote_hash:
                print(f"{os.path.basename(mapping_file)} is already up-to-date.")
                should_download = False
        except Exception as e:
            print(f"Could not verify update: {e}. Will download fresh copy.")

    if should_download:
        print("Downloading NIST 800-53 to MITRE ATT&CK mapping...")
        download_script = f"""
import requests, os, sys
url = '{mapping_url}'
try:
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open('{mapping_file}', 'wb') as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)
    print('Downloaded mapping to {mapping_file}')
except Exception as e:
    print(f'Failed to download mapping: {{e}}', file=sys.stderr)
    sys.exit(1)
"""
        subprocess.run([python_cmd, "-c", download_script], check=True)


def run_demo(selected_model):
    """
    Launch the main demo application.
    """
    python_cmd = get_python_cmd()
    print(f"Starting NIST Compliance RAG Demo with model: {selected_model}")
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

    print("Select a SentenceTransformer model for embeddings:")
    for i, (name, desc) in enumerate(models, 1):
        print(f"  {i}: {name} - {desc}")
    while True:
        try:
            choice = int(input("\nEnter number (1-6): "))
            if 1 <= choice <= len(models):
                break
            print(f"Please enter a number between 1 and {len(models)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    selected_model = models[choice - 1][0]
    print(f"Selected model: {selected_model}\n")

    # Setup steps
    create_virtual_env(force_recreate=False)
    install_requirements()

    python_cmd = get_python_cmd()
    download_cci_xml(python_cmd)
    download_nist_attack_mapping(python_cmd)

    # Run demo
    run_demo(selected_model)


if __name__ == "__main__":
    main()
