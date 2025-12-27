import sys
import csv
from pathlib import Path
import xml.etree.ElementTree as ET

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
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = port.get("portid")
            protocol = port.get("protocol")

            results.setdefault(ip, set()).add(
                f"{portid}/{protocol}"
            )

def main():
    if len(sys.argv) < 3:
        print("Usage: python xml_open_ports.py <xml_file_or_dir> <output.csv>")
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
        writer.writerow(["IP", "Open_Ports"])

        for ip, ports in sorted(results.items()):
            writer.writerow([
                ip,
                " ".join(sorted(ports))
            ])

    print(f"[+] CSV generated: {output_csv}")

if __name__ == "__main__":
    main()
