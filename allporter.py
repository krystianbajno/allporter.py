import socket
import threading
import sys
import os
import concurrent.futures
import yaml

BLOCKLISTED_TCP_PORTS = set()
BLOCKLISTED_UDP_PORTS = set()
open_ports = []
connections = {}
lock = threading.Lock()
command_history = []
history_index = -1 

def load_blocklisted_ports(yaml_path):
    global BLOCKLISTED_TCP_PORTS, BLOCKLISTED_UDP_PORTS
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
            BLOCKLISTED_TCP_PORTS = set(data.get("blocklisted_ports", {}).get("tcp", []))
            BLOCKLISTED_UDP_PORTS = set(data.get("blocklisted_ports", {}).get("udp", []))
    except Exception as e:
        print(f"[!] Failed to load blocklist from {yaml_path}: {e}")

def scan_tcp_port(host, port):
    if port in BLOCKLISTED_TCP_PORTS:
        return
    try:
        with socket.create_connection((host, port), timeout=1):
            with lock:
                open_ports.append(port)
                connections[port] = True
                print(f"[+] Open TCP port: {port}")
    except (socket.timeout, socket.error):
        pass

def scan_udp_port(host, port):
    if port in BLOCKLISTED_UDP_PORTS:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (host, port))
        sock.recvfrom(1024)
        with lock:
            open_ports.append(port)
            connections[port] = True
            print(f"[+] Open UDP port: {port}")
    except (socket.timeout, socket.error):
        pass

def scan_all_ports(host, scan_tcp=True, scan_udp=False):
    print("[*] Scanning ports...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        if scan_tcp:
            futures.extend(executor.submit(scan_tcp_port, host, port) for port in range(1, 65536))
        if scan_udp:
            futures.extend(executor.submit(scan_udp_port, host, port) for port in range(1, 65536))
        concurrent.futures.wait(futures)
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

def get_or_create_connection(host, port, is_udp=False):
    sock = connections.get(port)
    if sock:
        try:
            if is_udp:
                sock.sendto(b'', (host, port))
            else:
                sock.send(b'')
            return sock
        except (socket.error, BrokenPipeError):
            print(f"[!] Reconnecting to {host}:{port} (previous connection dropped)")
            close_connection(port)

    return create_new_connection(host, port, is_udp)

def create_new_connection(host, port, is_udp=False):
    try:
        if is_udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(b'', (host, port))
        else:
            sock = socket.create_connection((host, port), timeout=5)
        connections[port] = sock
        print(f"[+] Connected to {host}:{port}")
        return sock
    except (socket.error, ConnectionRefusedError) as e:
        print(f"[-] Error connecting to {host}:{port}: {e}")
        return None

def close_connection(port):
    sock = connections.pop(port, None)
    if sock:
        sock.close()
        print(f"[+] Connection to port {port} closed.")

def input_with_history(prompt):
    global history_index
    while True:
        user_input = input(prompt)

        if user_input == "":
            history_index = len(command_history)
            continue

        if user_input == "UP":
            if history_index > 0:
                history_index -= 1
                return command_history[history_index]
            else:
                return ""
        elif user_input == "DOWN":
            if history_index < len(command_history) - 1:
                history_index += 1
                return command_history[history_index]
            else:
                return ""
        else:
            command_history.append(user_input)
            history_index = len(command_history)
            return user_input

def interact_with_port(host, port, is_udp=False):
    sock = get_or_create_connection(host, port, is_udp)
    if sock is None:
        print(f"[-] Unable to connect to {host}:{port}.")
        return

    print(f"[+] Connected to {host}:{port}. Type commands, 'load_payload' or 'exit'.\n")
    try:
        while True:
            cmd = input_with_history(f"$ [{host}:{port}] > ")
            if cmd.lower() in ('exit', 'quit'):
                return
            elif cmd.lower().startswith('load_payload'):
                try:
                    _, file_path = cmd.split(maxsplit=1)
                    send_payload(sock, file_path)
                except ValueError:
                    print("[-] Usage: load_payload <file>")
            else:
                try:
                    if is_udp:
                        sock.sendto(cmd.encode() + b'\n', (host, port))
                    else:
                        sock.sendall(cmd.encode() + b'\n')
                    response = sock.recv(4096)
                    if not response:
                        raise ConnectionResetError
                    print(response.decode(errors='ignore'))
                except socket.timeout:
                    print("[-] No response.")
                except (ConnectionResetError, BrokenPipeError):
                    print(f"[!] Connection to {host}:{port} was closed.")
                    close_connection(port)
                    return
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Exiting session.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_host> [-u] [-t] [ports]")
        sys.exit(1)

    target_host = sys.argv[1]
    scan_tcp = True
    scan_udp = False

    if '-u' in sys.argv:
        scan_udp = True
        if '-t' not in sys.argv:
            scan_tcp = False

    specified_ports = [int(port) for port in sys.argv[3:]] if len(sys.argv) > 3 else []

    load_blocklisted_ports("blocklist.yaml")

    if not specified_ports:
        scan_all_ports(target_host, scan_tcp, scan_udp)
        if not open_ports:
            print("[-] No open ports found.")
            return
    else:
        open_ports.extend(specified_ports)

    while True:
        print("\nSelect a port to interact with:")
        for idx, port in enumerate(open_ports):
            print(f"{idx}: Port {port}")

        print("Type 'port <number>' to manually connect to a port.")
        print("Type 'exit' to quit.")
        choice = input("> ")

        if choice.lower() in ('exit', 'quit'):
            break

        if choice.lower().startswith('port '):
            try:
                _, port_str = choice.split(maxsplit=1)
                port = int(port_str)

                if port in BLOCKLISTED_TCP_PORTS or port in BLOCKLISTED_UDP_PORTS:
                    print(f"[-] Port {port} is blacklisted.")
                    continue

                if port not in open_ports:
                    sock = get_or_create_connection(target_host, port, is_udp=scan_udp)
                    if sock:
                        open_ports.append(port)
                    else:
                        print(f"[-] Failed to connect to port {port}.")
                else:
                    print(f"[i] Port {port} already in the list.")
            except ValueError:
                print("[-] Usage: port <number>")
            continue

        try:
            idx = int(choice)
            if 0 <= idx < len(open_ports):
                is_udp = any(port == open_ports[idx] for port in open_ports)
                interact_with_port(target_host, open_ports[idx], is_udp)
            else:
                print("[-] Invalid index.")
        except ValueError:
            print("[-] Please enter a valid number or command.")

if __name__ == "__main__":
    main()
