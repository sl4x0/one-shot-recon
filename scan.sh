#!/bin/bash
ppath="$(pwd)"
scope_path="$ppath/scope/$id"

timestamp="$(date +%s)" 
scan_path="$ppath/scans/$timestamp"

# exit if scope path doesnt exist if [ ! -d "$scope_path" ]; then echo "Path doesn't exist" exit 1
if [! -d "$scope_path"]; then
  echo "Path dosen't exist"
  exit 1
fi

mkdir -p "$scan_path"
cd "$scan_path"
### PERFORM SCAN ###
echo "Starting scan against roots:" 
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt" 
sleep 3

# calculate time diff
end_time=$(date +%s)
seconds="$(expr $end_time - $timestamp)"
time=""

if [[ "$seconds" -gt 59 ]]
then
    minutes=$(expr $seconds / 60) 
    time="$minutes minutes"
else
    time="$seconds seconds"
fi
echo "Scan $id took $time"

# UTLS
# wget -O lists/pry-dns.txt https://i.pry0.cc/lists/pry-dns.txt
# wget -O lists/resolvers.txt https://i.pry0.cc/lists/resolvers.txt

### PERFORM SCAN ###
echo "Starting scan against roots"
cat "$scope_path/root.txt"
cp -v "$scope_path/root.txt" "$scan_path/roots.txt"

# DNS ENUMERATION
cat "$scan_path/roots.txt" | haktrails subdomains | anew subs.txt | wc -l
cat "$scan_path/roots.txt" | subfinder -all | anew subs.txt | wc -l
cat "$scan_path/roots.txt" | shuffledns -w ~/wordlist/pry-dns.txt -r ~/wordlist/resolvers.txt | anew subs.txt | wc -l

# Dns Resolution
puredns resolve "$scan_path/subs.txt" -r ~/wordlist/resolvers.txt -w "$scan_path/resolved.txt" | wc -l
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json" | jq -r '.a?[]?' | anew "$scan_path/ips.txt" | wc -l


# Port Scanning & HTTP Server Discovery
nmap -T 4 -vv -iL "$scan_path/ips.txt" --top-ports 3000 -n --open -oX "$scan_path/nmap.xml"
tew -x "$scan_path/nmap.xml" -dnsx "$scan_path/dns.json" —vhost -o "$scan_path/hostport.txt" | httpx -json -o "$scan_path/http.json"

# extract the HTTP URLs
cat "$scan_path/http.json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u >"$scan_path/http.txt"

# HTTP Crawling
gospider -S "$scan_path/http.txt" —json | grep '{' | jq -r '.output?' | tee -a "$scan_path/crawl.txt"

# Javascript Pulling
cat "$scan_path/crawl.txt" | grep "\.js" | httpx -sr -srd js

#############################

# recursively grep through your data
# grep -Hrni ‘set-cookie’ —-color=always | batcat

# Using gf
# gf aws-keys

# To find further starting points for enumeration, use tok.
# find . -type f | tok | sort | uniq -c | sort -rn | head -n 40

# cat crawl.txt | grep "?" | qsreplace ../../../../etc/passwd | ffuf -u 'FUZZ' -w - -mr '^root:'
