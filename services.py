import sys
import csv
from pathlib import Path
import xml.etree.ElementTree as ET

def parse_xml_file(xml_file, rows):
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
            protocol = port.get("protocol")
            portid = port.get("portid")

            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port.find("service")
            if service_elem is None:
                continue

            service = service_elem.get("name", "")
            product = service_elem.get("product", "")

            rows.append([
                ip,
                f"{portid}/{protocol}",
                service,
                product
            ])

def main():
    if len(sys.argv) < 3:
        print("Usage: python xml_ports_to_csv.py <xml_file_or_dir> <output.csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_csv = sys.argv[2]

    rows = []

    if input_path.is_file() and input_path.suffix == ".xml":
        parse_xml_file(input_path, rows)

    elif input_path.is_dir():
        for xml_file in input_path.glob("*.xml"):
            parse_xml_file(xml_file, rows)

    else:
        print("Invalid input path")
        sys.exit(1)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Service", "Version"])
        writer.writerows(rows)

    print(f"[+] CSV generated: {output_csv}")

if __name__ == "__main__":
    main()
