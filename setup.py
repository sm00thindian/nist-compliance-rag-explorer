import os
import subprocess
import sys
import shutil
import configparser
import hashlib

VENV_DIR = "venv"
PYTHON_312 = "/opt/homebrew/bin/python3.12"
KNOWLEDGE_DIR = "knowledge"

def check_python_binary():
    if not os.path.exists(PYTHON_312):
        print(f"Error: {PYTHON_312} not found. Install Python 3.12 via Homebrew: 'brew install python@3.12'")
        sys.exit(1)
    print(f"Using Python 3.12 at {PYTHON_312}")

def create_virtual_env(force_recreate=False):
    if force_recreate and os.path.exists(VENV_DIR):
        print(f"Removing existing virtual environment in {VENV_DIR}...")
        shutil.rmtree(VENV_DIR)
    if not os.path.exists(VENV_DIR):
        print(f"Creating virtual environment in {VENV_DIR}...")
        subprocess.run([PYTHON_312, "-m", "venv", VENV_DIR], check=True)
    else:
        print(f"Virtual environment already exists in {VENV_DIR}.")
    # Verify the Python executable exists
    python_cmd = get_python_cmd()
    if not os.path.exists(python_cmd):
        print(f"Error: Virtual environment Python not found at {python_cmd}. Recreating...")
        shutil.rmtree(VENV_DIR)
        subprocess.run([PYTHON_312, "-m", "venv", VENV_DIR], check=True)

def get_python_cmd():
    return os.path.join(VENV_DIR, "bin", "python3") if sys.platform != "win32" else os.path.join(VENV_DIR, "Scripts", "python.exe")

def install_requirements():
    python_cmd = get_python_cmd()
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found.")
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
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    cci_file = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    cci_url = config.get('DEFAULT', 'cci_url', fallback='https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip')
    if os.path.exists(cci_file):
        print(f"{cci_file} already exists.")
        return
    print("Downloading CCI XML...")
    subprocess.run([python_cmd, "-m", "pip", "install", "requests"])
    subprocess.run([python_cmd, "-c", f"""
import requests, zipfile, os
url = '{cci_url}'
r = requests.get(url, stream=True); r.raise_for_status()
with open('U_CCI_List.zip', 'wb') as f:
    for chunk in r.iter_content(8192): f.write(chunk)
with zipfile.ZipFile('U_CCI_List.zip', 'r') as z: z.extract('U_CCI_List.xml')
os.rename('U_CCI_List.xml', '{cci_file}')
os.remove('U_CCI_List.zip')
print('Downloaded and extracted U_CCI_List.xml to {cci_file}')
"""], check=True)

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
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
        local_hash = get_file_hash(mapping_file)
        print(f"Checking if {mapping_file} is up-to-date...")
        subprocess.run([python_cmd, "-c", f"""
import requests, hashlib
r = requests.get('{mapping_url}', stream=True); r.raise_for_status()
remote_hash = hashlib.sha256(r.content).hexdigest()
with open('temp_hash.txt', 'w') as f: f.write(remote_hash)
"""], check=True)
        with open("temp_hash.txt", "r") as f:
            remote_hash = f.read().strip()
        os.remove("temp_hash.txt")
        if local_hash == remote_hash:
            print(f"{mapping_file} is already up-to-date.")
            should_download = False

    if should_download:
        print("Downloading NIST 800-53 to MITRE ATT&CK mapping...")
        subprocess.run([python_cmd, "-c", f"""
import requests, os
url = '{mapping_url}'
r = requests.get(url, stream=True); r.raise_for_status()
with open('{mapping_file}', 'wb') as f:
    for chunk in r.iter_content(8192): f.write(chunk)
print('Downloaded NIST 800-53 to MITRE ATT&CK mapping to {mapping_file}')
"""], check=True)

def run_demo(selected_model):
    python_cmd = get_python_cmd()
    subprocess.run([python_cmd, "-m", "src.main", "--model", selected_model], check=True, cwd=os.path.dirname(os.path.abspath(__file__)))

def main():
    check_python_binary()
    models = [
        ("all-MiniLM-L12-v2", "Fast, lightweight (12 layers)."),
        ("all-mpnet-base-v2", "Balanced performance and speed (default)."),
        ("multi-qa-MiniLM-L6-cos-v1", "Optimized for QA (6 layers)."),
        ("all-distilroberta-v1", "Distilled RoBERTa, good accuracy."),
        ("paraphrase-MiniLM-L6-v2", "Lightweight, excels at paraphrasing."),
        ("all-roberta-large-v1", "High accuracy, memory-intensive.")
    ]
    print("Select a model:")
    for i, (name, desc) in enumerate(models, 1):
        print(f"{i}: {name} - {desc}")
    while True:
        try:
            choice = int(input("Enter number (1-6): "))
            if 1 <= choice <= len(models):
                break
            print(f"Please enter a number between 1 and {len(models)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    selected_model = models[choice - 1][0]
    print(f"Selected model: {selected_model}")

    create_virtual_env(force_recreate=False)  # Set to True to force recreation
    install_requirements()
    python_cmd = get_python_cmd()
    download_cci_xml(python_cmd)
    download_nist_attack_mapping(python_cmd)
    run_demo(selected_model)

if __name__ == "__main__":
    main()
