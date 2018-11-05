#!/bin/sh

#CONFIG
conf="config/nmap.conf"
hosts="output/live-hosts.txt"
xml="output/nmap-output.xml"
nmapvulnxml="output/nmapvuln.xml"
nmapvuln2xml="output/nmapvuln2.xml"
nmapvulnjson="output/nmapvuln.json"
nmapvuln2json="output/nmapvuln2.json"
xml2json="plugins/xml2json/xml2json.py"
json="output/nmap-output.json"
domain="localhost"

## COLORS
red="\e[31m"
reset="\e[0m"
bold="\e[1m"
flicker="\e[5m"
lgreen="\e[92m"

#SCRIPT
clear
## SETUP
echo $red$bold"Starting Tool\n"$reset
mkdir output
echo $bold$lgreen"Starting up nessus"$reset
/etc/init.d/nessusd start
## nmap pingsweep
echo $bold$lgreen"Nmap scans"$reset
nmap -n -sS -iL $conf -oG - | awk '/Up$/{print $2}' > $hosts
echo $bold$lgreen"Pingsweep done"$reset
## nmap service detection
nmap -sV -O -iL $hosts -oX $xml
echo $bold$lgreen"Service detection done"$reset
python $xml2json -t xml2json -o $json $xml
echo $bold$lgreen"Starting DNS scan"$reset
dnsscan $domain
echo $bold$lgreen"Starting nessus scan"$reset
nessusscan
echo $bold$lgreen"Starting nmap vulnerability scan"$reset
nmapvuln

## FUNCTIONS

#-------------------------------------------------------------------------------------------------------------------------------------------------

### DNS Scan
# FEATURE REQUEST: $domain should be autodetected and filled with all domains OR should be loaded from config
dnsscan(){
  dnsrecon -d $1 -D /usr/share/wordlists/dnsmap.txt -t axfr -j $(pwd)/dnsinfo.json
}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### Nmap Vulnerability scan
nmapvuln(){
nmap -Pn --script vuln -iL $hosts -oX $nmapvulnxml
nmap -sV --script vulscan.nse -iL $hosts -oX $nmapvuln2xml
python $xml2json -t xml2json -o $nmapvulnjson $nmapvulnxml
python $xml2json -t xml2json -o $nmapvuln2json $nmapvuln2xml

}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### Nessus Scan
nessusscan(){
# check if nessus is ready
echo $bold$lgreen"Checking if nessus is up"$reset
ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".folders")
while [ "$ready" = null ]
do
	echo "waiting for nessus"
	sleep 1
	ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".folders")
done

echo $bold$lgreen"Nessus is up"$reset

# get hosts seperated by comma's
hosts=$(sed ':a;N;$!ba;s/\n/,/g' output/live-hosts.txt)

echo $bold$lgreen"Creating nessus scan"$reset
# create a new nessus scan using the predefined policy uuid
scanid=$(echo "{\"uuid\": \"ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66\",\"settings\": {\"name\": \"AutoScan\",\"description\": \"a scan created by the automated script\",\"scanner_id\": 1,\"enabled\": \"true\",\"starttime\": \"20170820T100500\",\"launch\": \"YEARLY\",\"text_targets\": \"${hosts}\"}}" | http --verify=no POST https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".scan.id")
echo $scanid

echo $bold$lgreen"Starting the scan"$reset
# start the scan
http -v --verify=no POST https://localhost:8834/scans/$scanid/launch \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624"

# check periodically if the scan is finished and get the export id
scandone=$(echo "{\"format\": \"html\", \"chapters\": \"vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin;compliance\"}" | http --verify=no POST https://localhost:8834/scans/$scanid/export \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".file")
while [ "$scandone" = null ]
do
	echo "waiting for scan"
	sleep 1
	scandone=$(echo "{\"format\": \"html\", \"chapters\": \"vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin;compliance\"}" | http --verify=no POST https://localhost:8834/scans/$scanid/export \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".file")
done
echo $scandone

echo $bold$lgreen"Exporting scan"$reset
# export is done, then save the export
status=$(http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/status \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".status")
echo $status
while [ "$status" = loading ]
do
	echo "waiting for export"
	sleep 1
	status=$(http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/status \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".status")
done
http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/download \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" > output/nessus-output.html
}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### Recon-ng
reconng(){

}
