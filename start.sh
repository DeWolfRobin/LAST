# /bin/sh
clear
echo "Starting Tool\n"
nmap -n -sS -iL nmap-ips.txt -oG - | awk '/Up$/{print $2}' > scope.txt
nmap -sV -O -iL scope.txt -oX nmapresult.txt
python xml2json/xml2json.py -t xml2json -o nmapresults.json nmapresult.txt
#while true
#do
#echo -n "."
#sleep 0.5
#done
