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
nmap -n -sS -iL config/nmap.conf -oG - | awk '/Up$/{print $2}' > output/live-hosts.txt
echo "Pingsweep done"
nmap -sV -O -iL output/live-hosts.txt -oX output/nmap-output.xml
echo "Service detection done"
python plugins/xml2json/xml2json.py -t xml2json -o output/nmap-output.json output/nmap-output.xml
