import socket
import threading
import sys
import os
import concurrent.futures
import ipaddress
import argparse  # Import argparse module for better argument parsing

open_ports = []
connections = {}
lock = threading.Lock()

def load_blocklisted_ports(txt_path="blocklist.txt"):
    try:
        with open(txt_path, 'r') as f:
            blocklisted_ports = {int(line.strip()) for line in f.readlines() if line.strip().isdigit()}
            return blocklisted_ports
    except Exception as e:
        print(f"[!] Failed to load blocklist: {e}")
        return set()

BLOCKLISTED_PORTS = load_blocklisted_ports()

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
        print(f"[+] Payload sent from {file_path} to {sock.getpeername()}")
        
        # Wait for a response after sending the payload
        response = sock.recv(4096)
        if response:
            print(f"[+] Response from {sock.getpeername()}: {response.decode(errors='ignore')}")
        else:
            pass
    except Exception as e:
        print(f"[-] Error sending payload: {e}")

def scan_port(host, port, payload_file=None):
    if port in BLOCKLISTED_PORTS:
        return
    try:
        sock = socket.create_connection((host, port), timeout=1)
        with lock:
            open_ports.append(port)
            connections[port] = sock
            print(f"[+] Open port: {port}")

            # Send payload immediately after successful connection
            if payload_file:
                send_payload(sock, payload_file)
                
    except Exception as e:
        pass
        #print(f"[-] Error connecting to {host}:{port}: {e}")

def scan_all_ports(host, payload_file=None):
    print("[*] Scanning ports...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1024) as executor:
        futures = [executor.submit(scan_port, host, port, payload_file) for port in range(1, 65536)]
        concurrent.futures.wait(futures)
    print(f"[+] Scanning completed. Open ports: {open_ports}")

def get_or_create_connection(host, port, payload_file=None):
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

    try:
        sock = socket.create_connection((host, port), timeout=5)
        connections[port] = sock
        print(f"[+] Connected to {host}:{port}")
        
        # Send payload immediately after connection if provided
        if payload_file:
            send_payload(sock, payload_file)
        
        return sock
    except Exception as e:
        print(f"[-] Error connecting to {host}:{port}: {e}")
        return None


def interact_with_port(host, port, payload_file=None):
    sock = get_or_create_connection(host, port, payload_file)
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

def cidr_to_ips(cidr):
    try:
        network = ipaddress.IPv4Network(cidr)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        print(f"[-] Invalid CIDR block: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Port scanner and payload sender")
    
    # Positional argument for the target (host or CIDR block)
    parser.add_argument("target", help="Target host or CIDR block (e.g., 192.168.1.1 or 192.168.1.0/24)")

    # Optional argument for specifying ports (as a list of integers)
    parser.add_argument("ports", nargs="*", type=int, help="Ports to scan (e.g., 80 443 8080)")

    # Optional argument for the payload file
    parser.add_argument("--payload", type=str, help="Path to the payload file to send on connection")

    args = parser.parse_args()

    # Handle CIDR block
    if '/' in args.target:
        target_hosts = cidr_to_ips(args.target)
    else:
        target_hosts = [args.target]

    # Scan ports for each host
    for target_host in target_hosts:
        if not args.ports:
            scan_all_ports(target_host, args.payload)
            if not open_ports:
                print("[-] No open ports found.")
                continue
        else:
            open_ports.extend(args.ports)

        while True:
            print(f"\nSelect a port to interact with for {target_host}:")
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
                        print(f"[-] Port {port} is blocklisted.")
                        continue

                    if port not in open_ports:
                        sock = get_or_create_connection(target_host, port, args.payload)
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
                    interact_with_port(target_host, open_ports[idx], args.payload)
                else:
                    print("[-] Invalid index.")
            except ValueError:
                print("[-] Please enter a valid number or command.")

if __name__ == "__main__":
    main()
