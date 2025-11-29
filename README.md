# nmap_parser

## nmap_tcp
nmap -Pn -p- -v -sSV --script=vuln,discovery,version --max-rate 800 --max-retries 2 -T4 -iL file -oA file_tcp

## nmap_udp
nmap -sUV --top-ports 100 -T3 --max-rate 100 --max-retries 2 -iL file -oA file_udp 

## parse_weak_ciphers
awk '/Nmap scan report/ {ip=$NF} /^[0-9]+\/tcp/ {port=$1} /CBC|TLS_RSA/ {key=ip", "port; if(!seen[key]++) print key}' file.nmap

## parse_tls_1.0_1.1
awk '/Nmap scan report/ {ip=$NF} /^[0-9]+\/tcp/ {port=$1} /TLSv1\.(0|1)/ {key=ip", "port; if(!seen[key]++) print key}' file.nmap

## parse_services
awk '/Nmap scan report/ {ip=$NF} /^[0-9]+\/tcp/ {port=$1; state=$2; service=$3; version=""; for(i=4;i<=NF;i++) version=version" "$i; gsub(/^ +| +$/,"",version); if(state=="open"){key=ip","port; if(!seen[key]++) print ip",",port",",service",",version}}' file.nmap
