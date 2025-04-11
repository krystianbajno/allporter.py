import socket
import threading
import sys
import os
import concurrent.futures
import yaml

open_ports = []
connections = {}
lock = threading.Lock()

def load_blocklisted_ports(yaml_path="blocklist.yaml"):
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
            return set(data.get("blocklisted_ports", []))
    except Exception as e:
        print(f"[!] Failed to load blocklist: {e}")
        return set()

BLOCKLISTED_PORTS = load_blocklisted_ports()

def scan_port(host, port):
    if port in BLOCKLISTED_PORTS:
        return
    try:
        sock = socket.create_connection((host, port), timeout=1)
        with lock:
            open_ports.append(port)
            connections[port] = sock
            print(f"[+] Open port: {port}")
    except:
        pass

def scan_all_ports(host):
    print("[*] Scanning ports...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1024) as executor:
        futures = [executor.submit(scan_port, host, port) for port in range(1, 65536)]
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

def get_or_create_connection(host, port):
    sock = connections.get(port)
    if sock:
        try:
            sock.send(b'')  # Ping the connection to check if it’s still alive
            return sock
        except:
            print(f"[!] Reconnecting to {host}:{port} (previous connection dropped)")
            try:
                sock.close()  # Close the invalid connection
            except:
                pass
            del connections[port]

    # Establish new connection if not found or if the previous one failed
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
        print(f"[-] Unable to connect to {host}:{port}.")
        return

    print(f"[+] Connected to {host}:{port}. Type commands, 'load_payload' or 'exit'.\n")
    try:
        while True:
            cmd = input(f"{host}:{port}> ")
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
                    sock.sendall(cmd.encode() + b'\n')
                    response = sock.recv(4096)
                    if not response:
                        raise ConnectionResetError
                    print(response.decode(errors='ignore'))
                except socket.timeout:
                    print("[-] No response.")
                except (ConnectionResetError, BrokenPipeError):
                    print(f"[!] Connection to {host}:{port} was closed.")
                    if port in connections:
                        del connections[port]
                    return
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Exiting session.")
        return


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

                if port in BLOCKLISTED_PORTS:
                    print(f"[-] Port {port} is blacklisted.")
                    continue

                if port not in open_ports:
                    sock = get_or_create_connection(target_host, port)
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
                interact_with_port(target_host, open_ports[idx])
            else:
                print("[-] Invalid index.")
        except ValueError:
            print("[-] Please enter a valid number or command.")

if __name__ == "__main__":
    main()
