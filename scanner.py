import socket
import threading
import argparse
import time
import logging
import ipaddress
import os
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Create output folder
os.makedirs("output", exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='output/scan_log.txt',
    filemode='w',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Thread-safe list and lock for open ports
open_ports = []
lock = threading.Lock()

def scan_port(ip: str, port: int, timeout: int = 1, pbar=None) -> None:
    """
    Attempts to connect to a specified TCP port on a given IP address.

    Args:
        ip (str): Target IP address.
        port (int): Port number to scan.
        timeout (int): Timeout duration for the socket connection in seconds.
        pbar (tqdm): Progress bar instance.

    Prints and logs open ports.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                msg = f"[+] Port {port} is OPEN"
                print(Fore.GREEN + msg)
                logging.info(msg)
                with lock:
                    open_ports.append(port)
    except Exception as e:
        msg = f"[-] Error scanning port {port}: {e}"
        print(Fore.RED + msg)
        logging.error(msg)
    finally:
        if pbar:
            pbar.update(1)

def validate_ip_or_resolve(ip_or_host: str) -> str:
    """
    Validates an IP address or resolves a hostname to an IP address.

    Args:
        ip_or_host (str): The IP address or hostname string.

    Returns:
        str: Resolved IP address or original IP if valid.
    """
    try:
        ipaddress.ip_address(ip_or_host)
        return ip_or_host
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(ip_or_host)
            print(Fore.CYAN + f"[🔍] Resolved {ip_or_host} to {resolved_ip}")
            return resolved_ip
        except socket.gaierror:
            print(Fore.RED + "[-] Invalid hostname or IP.")
            exit(1)

def parse_arguments():
    """
    Parses command-line arguments using argparse.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Ultimate Python TCP Port Scanner"
    )
    parser.add_argument("ip", help="Target IP address or hostname")
    parser.add_argument("-s", "--start", type=int, default=1,
                        help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024,
                        help="End port (default: 1024)")
    parser.add_argument("-t", "--timeout", type=int, default=1,
                        help="Socket timeout in seconds (default: 1)")

    return parser.parse_args()

def save_open_ports(ip: str) -> None:
    """
    Saves the list of open ports to a file named 'output/open_ports.txt'.

    Args:
        ip (str): Target IP address.
    """
    output_file = "output/open_ports.txt"
    if open_ports:
        with open(output_file, "w") as f:
            f.write(f"Open ports on {ip}:\n")
            for port in open_ports:
                f.write(f"{port}\n")
        print(Fore.CYAN + f"[💾] Saved open ports to {output_file}")
    else:
        print(Fore.YELLOW + "[!] No open ports found to save.")

def main():
    """
    Main execution function that performs the port scanning logic.
    Validates input, starts threads for each port, tracks progress, logs results,
    and saves open ports to a file.
    """
    args = parse_arguments()
    ip = validate_ip_or_resolve(args.ip)

    print(Fore.BLUE + f"[*] Scanning {ip} from port {args.start} to {args.end}...\n")
    start_time = time.time()

    total_ports = args.end - args.start + 1
    pbar = tqdm(total=total_ports, desc="Scanning", ncols=70)

    threads = []
    for port in range(args.start, args.end + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, args.timeout, pbar))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    pbar.close()
    duration = time.time() - start_time
    print(Fore.MAGENTA + f"\n[✔] Scan completed in {duration:.2f} seconds.")

    save_open_ports(ip)

if __name__ == "__main__":
    main()
