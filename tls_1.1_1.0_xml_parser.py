import xml.etree.ElementTree as ET
import csv
import sys
from pathlib import Path

def parse_xml(file_path, writer):
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr")

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            portid = port.get("portid")
            protocol = port.get("protocol")

            tls10 = "No"
            tls11 = "No"

            for script in port.findall("script"):
                if script.get("id") == "ssl-enum-ciphers":
                    for table in script.findall(".//table"):
                        key = table.get("key")
                        if key == "TLSv1.0":
                            tls10 = "Yes"
                        elif key == "TLSv1.1":
                            tls11 = "Yes"

            # Write only if weak TLS exists
            if tls10 == "Yes" or tls11 == "Yes":
                writer.writerow([ip, portid, protocol, tls10, tls11])

def main():
    if len(sys.argv) < 3:
        print("Usage: python tls_xml_to_csv.py <xml_file | directory> <output.csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_csv = sys.argv[2]

    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Port", "Protocol", "TLSv1.0", "TLSv1.1"])

        if input_path.is_file() and input_path.suffix == ".xml":
            parse_xml(input_path, writer)

        elif input_path.is_dir():
            for xml_file in input_path.glob("*.xml"):
                parse_xml(xml_file, writer)

        else:
            print("Invalid input. Provide an XML file or directory.")
            sys.exit(1)

    print(f"[+] CSV report generated: {output_csv}")

if __name__ == "__main__":
    main()
