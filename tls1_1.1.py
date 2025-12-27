import re
import sys
from pathlib import Path

TLS_REGEX = re.compile(r"(TLSv1\.0|TLSv1\.1)")
IP_REGEX = re.compile(r"Nmap scan report for ([\d\.]+)")
PORT_REGEX = re.compile(r"(\d+)/(tcp|udp)\s+open")

def parse_nmap_file(file_path):
    ip = None
    port = None

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            # Capture IP
            ip_match = IP_REGEX.search(line)
            if ip_match:
                ip = ip_match.group(1)
                port = None
                continue

            # Capture Port
            port_match = PORT_REGEX.search(line)
            if port_match:
                port = f"{port_match.group(1)}/{port_match.group(2)}"
                continue

            # Detect TLS 1.0 / 1.1
            tls_match = TLS_REGEX.search(line)
            if tls_match and ip and port:
                print(f"{ip} {port} {tls_match.group(1)}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python tls_extract.py <file.nmap | directory>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_file() and path.suffix == ".nmap":
        parse_nmap_file(path)

    elif path.is_dir():
        for nmap_file in path.glob("*.nmap"):
            parse_nmap_file(nmap_file)

    else:
        print("Invalid input. Provide a .nmap file or directory containing .nmap files.")

if __name__ == "__main__":
    main()
