# nmap_parser

## nmap_tcp
nmap -Pn -p- -v -sSV --script=vuln,discovery,version --max-rate 800 --max-retries 2 -T4 -iL file -oA file_tcp

## nmap_udp
nmap -sUV --top-ports 100 -T3 --max-rate 100 --max-retries 2 -iL file -oA file_udp 

## parse_weak_ciphers


## parse_tls_1.0_1.1
https://github.com/niyosh/nmap_parser/blob/main/tls1_1.1.py

## parse_services

