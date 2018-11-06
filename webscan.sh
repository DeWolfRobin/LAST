ports=80,443,8080,8443
ips=$(cat output/live-hosts.txt | sed 's/\n/,/g')
rm output/nikto.xml

niktoscan() {
	nikto -host $1 -port $2 -Format xml -output output/nikto.xml
	python plugins/xml2json/xml2json.py -t xml2json -o output/nikto.json output/nikto.xml
}

checklive() {
if (curl -s $1:$2) then
	echo "GOOD"
else
	echo "host unreachable"
fi
}

niktoscan $ips $ports
