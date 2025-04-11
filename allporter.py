import socket
import threading
import sys
import os

BLACKLISTED_PORTS = {
    # Microsoft RPC/SMB/NetBIOS
    135, 137, 138, 139, 445,
    
    # LDAP
    389, 636, 3268, 3269,
    
    # Database services
    1433,   # MS SQL Server
    1521,   # Oracle DB
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB

    # Remote desktop and terminal services
    3389,   # RDP
    22,     # SSH (optional, in case you want to skip it)
    23,     # Telnet

    # Email servers (optional)
    25,     # SMTP
    110,    # POP3
    143,    # IMAP

    # Web servers (optional)
    80,     # HTTP
    443,    # HTTPS
}

open_ports = []
connections = {}
lock = threading.Lock()

def scan_port(host, port):
    if port in BLACKLISTED_PORTS:
        return
    try:
        with socket.create_connection((host, port), timeout=1) as sock:
            with lock:
                open_ports.append(port)
                print(f"[+] Open port: {port}")
    except:
        pass

def scan_all_ports(host):
    threads = []
    print("[*] Scanning ports...")
    for port in range(1, 65536):
        t = threading.Thread(target=scan_port, args=(host, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(f"[+] Scanning completed. Open ports: {open_ports}")

def load_payload(file_path):
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} not found.")
        return None
    with open(file_path, 'rb') as f:
        return f.read()

def send_payload(sock, file_path):
    payload = load_payload(file_path)
    if payload is None:
        return
    try:
        sock.sendall(payload)
        print(f"[+] Payload sent from {file_path}")
    except Exception as e:
        print(f"[-] Error sending payload: {e}")

def get_or_create_connection(host, port):
    if port in connections and connections[port].connected:
        return connections[port]
    try:
        sock = socket.create_connection((host, port), timeout=5)
        connections[port] = sock
        print(f"[+] Connected to {host}:{port}")
        return sock
    except Exception as e:
        print(f"[-] Error connecting to {host}:{port}: {e}")
        return None

def interact_with_port(host, port):
    sock = get_or_create_connection(host, port)
    if sock is None:
        return
    print(f"[+] Connected to {host}:{port}. Type commands or 'exit'.\n")
    while True:
        cmd = input(f"{host}:{port}> ")
        if cmd.lower() in ('exit', 'quit'):
            break
        elif cmd.lower().startswith('load_payload'):
            _, file_path = cmd.split(maxsplit=1)
            send_payload(sock, file_path)
        else:
            sock.sendall(cmd.encode() + b'\n')
            try:
                response = sock.recv(4096)
                print(response.decode(errors='ignore'))
            except socket.timeout:
                print("[-] No response.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_host> [ports]")
        sys.exit(1)

    target_host = sys.argv[1]
    specified_ports = [int(port) for port in sys.argv[2:]] if len(sys.argv) > 2 else []

    if not specified_ports:
        scan_all_ports(target_host)
        if not open_ports:
            print("[-] No open ports found.")
            return
    else:
        open_ports.extend(specified_ports)

    while True:
        print("\nSelect a port to interact with (or type 'exit'):")
        for idx, port in enumerate(open_ports):
            print(f"{idx}: Port {port}")
        choice = input("> ")
        if choice.lower() in ('exit', 'quit'):
            break
        try:
            idx = int(choice)
            if 0 <= idx < len(open_ports):
                interact_with_port(target_host, open_ports[idx])
            else:
                print("[-] Invalid index.")
        except ValueError:
            print("[-] Please enter a valid number.")

if __name__ == "__main__":
    main()
