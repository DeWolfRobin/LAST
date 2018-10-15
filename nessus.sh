POLUUID="ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66"
hosts=$(sed ':a;N;$!ba;s/\n/,/g' output/live-hosts.txt)
echo $hosts
msfconsole -n -q -x "clear;load nessus;nessus_connect admin:admin@localhost:8834;nessus_scan_new $POLUUID testing testscan $hosts;"
