import os
import subprocess
import sys
import shutil
import configparser
import hashlib


# === PATHS ===
VENV_DIR = "venv"
KNOWLEDGE_DIR = "knowledge"


# === PYTHON DISCOVERY ===
def find_supported_python():
    candidates = []
    if sys.platform == "win32":
        python_exe = shutil.which("python")
        if python_exe:
            candidates.append(python_exe)
    else:
        for suffix in ["3.12", "3.11", "3.10", "3"]:
            exe = shutil.which(f"python{suffix}")
            if exe:
                candidates.append(exe)

    for candidate in candidates:
        try:
            version_output = subprocess.check_output(
                [candidate, "--version"],
                stderr=subprocess.STDOUT,
                text=True
            ).strip()
            if any(version_output.startswith(f"Python 3.{v}") for v in [10, 11, 12]):
                return candidate, version_output
        except Exception:
            continue
    return None, None


def check_python_binary():
    python_path, version = find_supported_python()
    if not python_path:
        print("Error: Python 3.10, 3.11, or 3.12 required.")
        print("Download: https://www.python.org/downloads/")
        sys.exit(1)
    print(f"Using {version} at {python_path}")
    return python_path


def create_virtual_env(force_recreate=False):
    python_path = check_python_binary()
    if force_recreate and os.path.exists(VENV_DIR):
        print(f"Removing existing venv in {VENV_DIR}...")
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    if not os.path.exists(VENV_DIR):
        print(f"Creating virtual environment in {VENV_DIR}...")
        subprocess.run([python_path, "-m", "venv", VENV_DIR], check=True)
    else:
        print(f"Virtual environment exists in {VENV_DIR}.")
    python_cmd = get_python_cmd()
    if not os.path.exists(python_cmd):
        print(f"Recreating venv — Python not found at {python_cmd}")
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        subprocess.run([python_path, "-m", "venv", VENV_DIR], check=True)


def get_python_cmd():
    return os.path.join(VENV_DIR, "Scripts", "python.exe") if sys.platform == "win32" else os.path.join(VENV_DIR, "bin", "python3")


# === INSTALL REQUIREMENTS ===
def install_requirements():
    python_cmd = get_python_cmd()
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found.")
        sys.exit(1)

    print("Installing dependencies...")
    print("  Step 1/3: Upgrading pip...", end=" ", flush=True)
    subprocess.run([python_cmd, "-m", "pip", "install", "--upgrade", "pip", "--quiet"], check=True)
    print("complete")

    try:
        from tqdm import tqdm as tqdm_lib
        TQDM_AVAILABLE = True
    except ImportError:
        TQDM_AVAILABLE = False
        def tqdm_lib(iterable, **kwargs):
            return iterable

    print("  Step 2/3: Installing requirements...", flush=True)
    
    requirements = []
    with open("requirements.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                requirements.append(line)

    for req in (tqdm_lib(requirements, desc="Packages", unit="pkg") if TQDM_AVAILABLE else requirements):
        result = subprocess.run(
            [python_cmd, "-m", "pip", "install", req, "--quiet"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"\nFailed to install {req}")
            print(result.stderr.strip())
            sys.exit(1)

    print("  Step 3/3: Installing spaCy model...", end=" ", flush=True)
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    spacy_model = config.get('DEFAULT', 'spacy_model', fallback='en_core_web_trf')

    check_cmd = [python_cmd, "-m", "spacy", "validate"]
    check_result = subprocess.run(check_cmd, capture_output=True, text=True)
    if spacy_model in check_result.stdout:
        print(f"Model '{spacy_model}' already installed")
    else:
        print("\n   Downloading...")
        download_cmd = [python_cmd, "-m", "spacy", "download", spacy_model]
        result = subprocess.run(download_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Failed. Falling back to en_core_web_trf...")
            subprocess.run([python_cmd, "-m", "spacy", "download", "en_core_web_trf", "--force"], check=True)
        else:
            print(f"Downloaded '{spacy_model}'")
    print("complete")


# === DOWNLOAD DATA ===
def download_data():
    python_cmd = get_python_cmd()
    download_cci_xml(python_cmd)
    download_nist_attack_mapping(python_cmd)


def download_cci_xml(python_cmd):
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
r = requests.get(url, stream=True); r.raise_for_status()
with open('U_CCI_List.zip', 'wb') as f:
    for chunk in r.iter_content(8192): f.write(chunk)
with zipfile.ZipFile('U_CCI_List.zip') as z:
    z.extract('U_CCI_List.xml')
os.rename('U_CCI_List.xml', '{cci_file}')
os.remove('U_CCI_List.zip')
print('CCI XML downloaded')
"""
    subprocess.run([python_cmd, "-c", script], check=True)


def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def download_nist_attack_mapping(python_cmd):
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    mapping_file = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_attack-14.1-enterprise_json.json")
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    mapping_url = config.get('DEFAULT', 'nist_800_53_attack_mapping_url',
                             fallback='https://center-for-threat-informed-defense.github.io/mappings-explorer/data/nist_800_53/attack-14.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-14.1-enterprise_json.json')

    should_download = True
    if os.path.exists(mapping_file):
        try:
            result = subprocess.run(
                [python_cmd, "-c", f"import requests, hashlib; r=requests.get('{mapping_url}'); print(hashlib.sha256(r.content).hexdigest())"],
                capture_output=True, text=True, check=True
            )
            remote_hash = result.stdout.strip()
            if get_file_hash(mapping_file) == remote_hash:
                print(f"{os.path.basename(mapping_file)} is up-to-date.")
                should_download = False
        except:
            pass

    if should_download:
        print("Downloading NIST to ATT&CK mapping...")
        subprocess.run([python_cmd, "-c", f"""
import requests
r = requests.get('{mapping_url}', stream=True)
r.raise_for_status()
with open('{mapping_file}', 'wb') as f:
    for c in r.iter_content(8192): f.write(c)
print('Downloaded')
"""], check=True)


# === RUN DEMO ===
def run_demo(selected_model):
    python_cmd = get_python_cmd()
    print(f"\nLaunching demo with model: {selected_model}")
    # CORRECT PYTHONPATH: parent of src/
    env = os.environ.copy()
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # → /Users/kilynn/Projects/nist-compliance-rag-explorer
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = project_root + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = project_root
    subprocess.run([python_cmd, "-m", "src.main", "--model", selected_model], env=env, check=True)


# === RUN TESTS ===
def run_tests():
    print("Running tests...")
    python_cmd = get_python_cmd()
    result = subprocess.run([python_cmd, "-m", "unittest", "discover", "-s", "test", "-p", "test_*.py", "-v"])
    sys.exit(result.returncode)


# === DOCKER MODE ===
def docker_download_mode():
    print("Docker mode: Downloading knowledge data only...")
    create_virtual_env()
    install_requirements()
    download_data()
    print("Docker setup complete. Ready to run.")
    sys.exit(0)


# === MAIN ===
def main():
    models = [
        ("all-MiniLM-L12-v2", "Fast"),
        ("all-mpnet-base-v2", "Balanced"),
        ("multi-qa-MiniLM-L6-cos-v1", "QA"),
        ("all-distilroberta-v1", "Good"),
        ("paraphrase-MiniLM-L6-v2", "Paraphrase"),
        ("all-roberta-large-v1", "High accuracy"),
    ]

    print("Select embedding model:")
    for i, (name, desc) in enumerate(models, 1):
        print(f"  {i}: {name} - {desc}")
    while True:
        try:
            choice = int(input("\nEnter 1–6: "))
            if 1 <= choice <= 6:
                break
        except:
            pass
    selected_model = models[choice - 1][0]

    create_virtual_env()
    install_requirements()
    download_data()
    run_demo(selected_model)


# === ENTRY POINT ===
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            create_virtual_env()
            install_requirements()
            download_data()
            run_tests()
        elif sys.argv[1] == "--download-only":
            docker_download_mode()
    else:
        main()
