#!/bin/sh

#CONFIG
apikeys=$(cat config/apikey.conf)
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

## FUNCTIONS

#-------------------------------------------------------------------------------------------------------------------------------------------------

### DNS Scan
# FEATURE REQUEST: $domain should be autodetected and filled with all domains OR should be loaded from config
dnsscan ()
{
  dnsrecon -d $1 -D /usr/share/wordlists/dnsmap.txt -t axfr -j $(pwd)/dnsinfo.json
}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### Nmap Vulnerability scan
nmapvuln ()
{
nmap -Pn --script vuln -iL $hosts -oX $nmapvulnxml
nmap -sV --script vulscan.nse -iL $hosts -oX $nmapvuln2xml
python $xml2json -t xml2json -o $nmapvulnjson $nmapvulnxml
python $xml2json -t xml2json -o $nmapvuln2json $nmapvuln2xml
}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### Nessus Scan
nessusscan ()
{
# check if nessus is ready
echo $bold$lgreen"Checking if nessus is up"$reset
poluuid=$(http --verify=no https://localhost:8834/policies \X-ApiKeys:$apikeys | jq -r ".policies[0].template_uuid")
http -v --verify=no https://localhost:8834/policies \X-ApiKeys:$apikeys
ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:$apikeys | jq -r ".folders")
while [ "$ready" = null ]
do
	echo "waiting for nessus"
	sleep 1
	ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:$apikeys | jq -r ".folders")
done

echo $bold$lgreen"Nessus is up"$reset

# get hosts seperated by comma's
hostsed=$(sed ':a;N;$!ba;s/\n/,/g' output/live-hosts.txt)

echo $bold$lgreen"Creating nessus scan"$reset
# create a new nessus scan using the predefined policy uuid
scanid=$(echo "{\"uuid\": \"$poluuid\",\"settings\": {\"name\": \"AutoScan\",\"description\": \"a scan created by the automated script\",\"scanner_id\": 1,\"enabled\": \"true\",\"starttime\": \"20170820T100500\",\"launch\": \"YEARLY\",\"text_targets\": \"${hostsed}\"}}" | http --verify=no POST https://localhost:8834/scans \X-ApiKeys:$apikeys | jq -r ".scan.id")
echo $scanid

echo $bold$lgreen"Starting the scan"$reset
# start the scan
http -v --verify=no POST https://localhost:8834/scans/$scanid/launch \X-ApiKeys:$apikeys

# check periodically if the scan is finished and get the export id
scandone=$(echo "{\"format\": \"html\", \"chapters\": \"vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin;compliance\"}" | http --verify=no POST https://localhost:8834/scans/$scanid/export \X-ApiKeys:$apikeys | jq -r ".file")
while [ "$scandone" = null ]
do
	echo "waiting for scan"
	sleep 1
	scandone=$(echo "{\"format\": \"html\", \"chapters\": \"vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin;compliance\"}" | http --verify=no POST https://localhost:8834/scans/$scanid/export \X-ApiKeys:$apikeys | jq -r ".file")
done
echo $scandone

echo $bold$lgreen"Exporting scan"$reset
# export is done, then save the export
status=$(http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/status \X-ApiKeys:$apikeys | jq -r ".status")
echo $status
while [ "$status" = loading ]
do
	echo "waiting for export"
	sleep 1
	status=$(http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/status \X-ApiKeys:$apikeys | jq -r ".status")
done
http --verify=no https://localhost:8834/scans/$scanid/export/$scandone/download \X-ApiKeys:$apikeys > output/nessus-output.html
}

#-------------------------------------------------------------------------------------------------------------------------------------------------

### 
rpc(){
out=$(rpcclient -U '' -N $1 -c querydominfo | sed 's/\t//g' | sed '$!s/$/","/g' | sed 's/:/":"/g')
array=$(rpcclient -U '' -N $1 -c enumdomusers | sed 's/rid:\[.*$//g' | sed '$!s/$/,/g' | sed 's/user://g' | sed 's/ //g;s/\[//g;s/\]//g')
out="{\"${out}\",\"users\":\"[${array}]\"}"
echo $out > output/rpc.json
}

additionalscan(){
# for each live host complete a set of scans
#for here
#rpc <IP>
#end for
}


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
