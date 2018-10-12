# /bin/sh

#CONFIG
$conf = "config/nmap.conf"
$hosts = "output/live-hosts.txt"
$xml = "output/nmap-output.xml"
$xml2json = "plugins/xml2json/xml2json.py"
$json = "output/nmap-output.json"

#SCRIPT
clear
echo "Starting Tool\n"
nmap -n -sS -iL $conf -oG - | awk '/Up$/{print $2}' > $hosts
echo "Pingsweep done"
nmap -sV -O -iL $hosts -oX $xml
echo "Service detection done"
python $xml2json -t xml2json -o $json $xml
