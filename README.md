# nmap_parser

## weak_ciphers
awk '
/Nmap scan report/ { ip = $NF }
/^[0-9]+\/tcp/      { port = $1 }
/CBC|TLS_RSA/ {
    key = ip " " port
    if (!seen[key]++) print key
}
' file.nmap

## tls_1.0_1.1
awk '
/Nmap scan report/ { ip = $NF }
/^[0-9]+\/tcp/      { port = $1 }
/TLSv1\.(0|1)/ {
    key = ip " " port
    if (!seen[key]++) print key
}
' file.nmap

## parse_service
awk '
/Nmap scan report/ { ip = $NF }

/^[0-9]+\/tcp/ {
    port = $1
    state = $2
    service = $3
   version = ""
    for (i=6; i<=NF; i++) version = version " " $i
    gsub(/^ +| +$/, "", version)
   if (state == "open") {
        key = ip " " port
        if (!seen[key]++) {
            print ip, port, service, version
        }
    }
}
' file.nmap
