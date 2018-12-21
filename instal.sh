apt install dirmngr python3-pip
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
gpg --keyserver pgpkeys.mit.edu --recv-key  ED444FF07D8D0BF6
gpg -a --export ED444FF07D8D0BF6 | sudo apt-key add -
apt update
apt install jq enum4linux wkhtmltopdf nbtscan p7zip-full exploitdb snmp nmap xvfb -y
pip3 install httpie pdfkit
