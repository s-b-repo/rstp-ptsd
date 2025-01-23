How It Works:

    Reads a list of IPs from ips.txt.
    Runs nmap for each IP and saves results in <ip>.txt.
    Reads usernames & passwords from creds.txt (one per line in user:pass format).
    Uses ffplay to attempt RTSP logins with those credentials.
    Uses threads to handle multiple IPs simultaneously.
