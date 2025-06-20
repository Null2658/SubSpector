# scanner.py
import subprocess
import tempfile
import random
import os
import requests
import platform
import shutil
import zipfile
import stat

# ANSI color codes
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"

# List of common User-Agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 OPR/101.0.0.0"
]

def download_subfinder():
    """
    Download and install subfinder automatically
    """
    system = platform.system().lower()
    arch = platform.machine().lower()
    
    # Determine the correct download URL
    if system == "windows":
        if "64" in arch or "amd64" in arch:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_windows_amd64.zip"
            exe_name = "subfinder.exe"
        else:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_windows_386.zip"
            exe_name = "subfinder.exe"
    elif system == "linux":
        if "64" in arch or "amd64" in arch:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip"
        elif "arm64" in arch or "aarch64" in arch:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_arm64.zip"
        else:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_386.zip"
        exe_name = "subfinder"
    elif system == "darwin":  # macOS
        if "arm64" in arch:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_darwin_arm64.zip"
        else:
            url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_darwin_amd64.zip"
        exe_name = "subfinder"
    else:
        raise OSError(f"Unsupported operating system: {system}")
    
    print(f"{YELLOW}[scanner][download_subfinder]{RESET} Downloading subfinder from: {url}")
    
    try:
        # Download the file
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        zip_path = os.path.join(os.getcwd(), "subfinder.zip")
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"{GREEN}[scanner][download_subfinder]{RESET} Downloaded successfully")
        
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(os.getcwd())
        
        # Remove the zip file
        os.remove(zip_path)
        
        # Make executable on Unix systems
        exe_path = os.path.join(os.getcwd(), exe_name)
        if os.path.exists(exe_path) and os.name == 'posix':
            os.chmod(exe_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        
        print(f"{GREEN}[scanner][download_subfinder]{RESET} Subfinder installed successfully")
        return exe_path
        
    except Exception as e:
        print(f"{RED}[scanner][download_subfinder]{RESET} Error downloading subfinder: {e}")
        raise

def find_subfinder() -> str:
    """
    Find subfinder executable in PATH or common locations, download if not found
    """
    # First check if subfinder is in PATH
    subfinder_path = shutil.which("subfinder")
    if subfinder_path:
        return subfinder_path
    
    # If not in PATH, try common locations
    system = platform.system().lower()
    possible_paths = []
    
    if system == "windows":
        possible_paths = [
            os.path.join(os.getcwd(), "subfinder.exe"),
            os.path.join(os.getcwd(), "subfinder", "subfinder.exe"),
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "Microsoft", "WinGet", "Packages", "subfinder.exe"),
            "C:\\Program Files\\subfinder\\subfinder.exe",
            "C:\\Program Files (x86)\\subfinder\\subfinder.exe"
        ]
    else:  # Linux/Unix
        possible_paths = [
            os.path.join(os.getcwd(), "subfinder"),
            os.path.join(os.getcwd(), "subfinder", "subfinder"),
            "/usr/local/bin/subfinder",
            "/usr/bin/subfinder",
            "/snap/bin/subfinder",
            os.path.expanduser("~/.local/bin/subfinder"),
            os.path.expanduser("~/go/bin/subfinder")
        ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # If not found anywhere, download it automatically
    print(f"{YELLOW}[scanner][find_subfinder]{RESET} Subfinder not found, downloading automatically...")
    try:
        return download_subfinder()
    except Exception as e:
        raise FileNotFoundError(f"Could not find or download subfinder: {e}")

def run_subfinder(domain: str) -> set:
    """
    Invoke the Subfinder tool in silent mode to enumerate subdomains.
    """
    results = set()
    try:
        with tempfile.NamedTemporaryFile(mode="r+", delete=False) as tmp:
            output_file = tmp.name

        # Find subfinder executable
        subfinder_path = find_subfinder()

        # Make sure the binary is executable on Linux
        if os.name == 'posix':
            try:
                os.chmod(subfinder_path, 0o755)
            except:
                pass  # Ignore permission errors

        cmd = [subfinder_path, "-d", domain, "-silent", "-o", output_file]
        print(f"{CYAN}[scanner][run_subfinder]{RESET} Running Subfinder: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(output_file, "r") as f:
            for line in f:
                sub = line.strip()
                if sub:
                    results.add(sub)
        os.remove(output_file)
        print(f"{GREEN}[scanner][run_subfinder]{RESET} Found {len(results)} subdomains")
    except Exception as e:
        print(f"{RED}[scanner][run_subfinder]{RESET} Error running Subfinder: {e}")
    return results

def fetch_subdomains(domain: str) -> set:
    """
    Fetch subdomains using only Subfinder.
    """
    print(f"{CYAN}[+]{RESET} Running Subfinder (silent) for domain: {domain}")
    subs = run_subfinder(domain)
    print(f"{CYAN}[+]{RESET} Total unique subdomains found: {len(subs)}")
    return subs

class SubdomainScanner:
    """
    Class to handle subdomain scanning operations
    """
    def __init__(self, domain):
        self.domain = domain
        
    def scan(self) -> list:
        """
        Perform subdomain scanning using available tools
        """
        subdomains = run_subfinder(self.domain)
        return list(subdomains)  # Convert set to list for JSON serialization
