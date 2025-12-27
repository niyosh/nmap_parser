import sys
import csv
from pathlib import Path
import xml.etree.ElementTree as ET

WEAK_KEYWORDS = [
    "RC4",
    "3DES",
    "DES",
    "MD5",
    "NULL",
    "EXPORT",
    "CBC",
    "SHA",
    "TLS_RSA"
]

def is_weak_cipher(cipher):
    cipher = cipher.upper()
    return any(w in cipher for w in WEAK_KEYWORDS)

def parse_xml(xml_file, results):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue

        ip = addr.get("addr")

        for port in host.findall(".//port"):
            portid = port.get("portid")
            proto = port.get("protocol")

            for script in port.findall("script[@id='ssl-enum-ciphers']"):
                # Find TLSv1.2 table explicitly
                tls12_table = script.find(".//table[@key='TLSv1.2']")
                if tls12_table is None:
                    continue

                # Find ALL cipher tables under TLSv1.2
                for cipher_table in tls12_table.findall(".//table"):
                    cipher_name = cipher_table.get("key")
                    if cipher_name and is_weak_cipher(cipher_name):
                        results.setdefault(ip, set()).add(
                            f"{portid}/{proto}"
                        )
                        break  # one weak cipher is enough per port

def main():
    if len(sys.argv) < 3:
        print("Usage: python tls12_weak.py <xml_file_or_dir> <output.csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_csv = sys.argv[2]

    results = {}

    if input_path.is_file():
        parse_xml(input_path, results)
    else:
        for xml in input_path.glob("*.xml"):
            parse_xml(xml, results)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Ports_with_TLS1.2_Weak_Ciphers"])

        for ip in sorted(results):
            writer.writerow([ip, " ".join(sorted(results[ip]))])

    print(f"[+] CSV generated: {output_csv}")

if __name__ == "__main__":
    main()
