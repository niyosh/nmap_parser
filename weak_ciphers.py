import sys
import csv
from pathlib import Path
import xml.etree.ElementTree as ET

WEAK_KEYWORDS = [
    "CBC", "SHA", "RSA", "3DES", "DES",
    "RC4", "MD5", "NULL", "EXPORT", "TLS_RSA"
]

def is_policy_weak(cipher_name):
    cipher_name = cipher_name.upper()
    return any(k in cipher_name for k in WEAK_KEYWORDS)

def parse_xml_file(xml_file, results):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue

        ip = addr.get("addr")
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            portid = port.get("portid")
            protocol = port.get("protocol")

            for script in port.findall("script"):
                if script.get("id") != "ssl-enum-ciphers":
                    continue

                for tls_table in script.findall("table"):
                    if tls_table.get("key") != "TLSv1.2":
                        continue

                    for cipher_group in tls_table.findall("table"):
                        if cipher_group.get("key") != "ciphers":
                            continue

                        for cipher in cipher_group.findall("table"):
                            cipher_name = None

                            for elem in cipher.findall("elem"):
                                if elem.get("key") == "name":
                                    cipher_name = elem.text

                            if cipher_name and is_policy_weak(cipher_name):
                                results.setdefault(ip, set()).add(
                                    f"{portid}/{protocol}"
                                )

def main():
    if len(sys.argv) < 3:
        print("Usage: python tls12_policy_weak.py <xml_file_or_dir> <output.csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_csv = sys.argv[2]

    results = {}

    if input_path.is_file():
        parse_xml_file(input_path, results)
    elif input_path.is_dir():
        for xml_file in input_path.glob("*.xml"):
            parse_xml_file(xml_file, results)
    else:
        print("Invalid input path")
        sys.exit(1)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Ports_with_TLS1.2_Weak_Ciphers"])

        for ip, ports in sorted(results.items()):
            writer.writerow([ip, " ".join(sorted(ports))])

    print(f"[+] CSV generated: {output_csv}")

if __name__ == "__main__":
    main()
