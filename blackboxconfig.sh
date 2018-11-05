nmcli dev show wlan0 | grep IP4.ADDRESS | cut -d ':' -f2 | tr -d '[:space:]' > config/nmap.conf

