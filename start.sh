# /bin/sh
clear
echo "Starting Tool\n"
nmap -sn -iL nmap-ips.txt -oX pingscanresult.txt
python xml2jsonSub/xml2json.py -t xml2json -o pingresult.json pingscanresult.txt
#while true
#do
#echo -n "."
#sleep 0.5
#done
