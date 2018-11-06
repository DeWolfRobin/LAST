import json
from pprint import pprint

out = {}
# filterWords = ["failed", "TIMEOUT", "Couldn't find", "FourOhFourRequest"]
# allowedFilteredWords = ["VULNERABLE"]
noVulFound = "None found"

# TODO check if there are actually multiple hosts

def readInitialNmap(pathToFile):
    with open(pathToFile) as f:
        data = json.load(f)
        hostinfo = data["nmaprun"]["host"]

        for host in hostinfo:
            for address in host["address"]:
                if 'ipv4' in address.values():
                    ipadres=address["@addr"]
            out[ipadres] = {}

            out[ipadres]['OS'] = {}
            if 'osmatch' in host["os"]:
                if type(host["os"]["osmatch"])==list:
                    for ops in host["os"]["osmatch"]:
                        out[ipadres]['OS'][ops["@line"]] = ops["@name"]
                else:
                    out[ipadres]['OS'][host["os"]["osmatch"]["@line"]] = host["os"]["osmatch"]["@name"]

            out[ipadres]['Ports'] = {}
            if type(host["ports"]["port"])==list:
                for value in host["ports"]["port"]:
                    currentport = value["@portid"]
                    out[ipadres]['Ports'][currentport] = {}
                    out[ipadres]['Ports'][currentport]['protocol'] = value["@protocol"]
                    out[ipadres]['Ports'][currentport]['service'] = value["service"]["@name"]
            else:
                out[ipadres]['Ports'][currentport] = {}
                out[ipadres]['Ports'][currentport]['protocol'] = host["ports"]["port"]["@protocol"]
                out[ipadres]['Ports'][currentport]['service'] = host["ports"]["port"]["service"]["@name"]

def addVulnFindingsToKey(arg, ip):
    currentBlock = out[ip]
    currentBlock['Vulnerabilities'] = {}
    portsOfIP = arg['ports']

    if type(portsOfIP['port'])==list:
        for port in portsOfIP['port']:
            currentBlock['Vulnerabilities'][port['@portid']] = {}
            if 'script' in port:
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
                if type(port['script'])==list:
                    for vultest in port['script']:
                        # if not any(word in vultest["@output"] for word in filterWords) or any(word in vultest["@output"] for word in allowedFilteredWords):
                        currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][vultest['@id']] = str(vultest['@output'])
                else:
                    currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] =  str(port['script']['@output'])
            else:
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = noVulFound
    else:
        currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']] = {}
        if 'script' in portsOfIP['port']:
            if type(port['script'])==list:
                for vultest in port['script']:
                    currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
                    currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][vultest['@id']] = str(vultest['@output'])
        else:
            currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']]["Nmap-Vuln"] = noVulFound


def addVulscanFindingsToKey(arg, ip):
    currentBlock = out[ip]
    currentVulBlock = currentBlock['Vulnerabilities']
    portsOfIP = arg['ports']

    if type(portsOfIP['port'])==list:
        for port in portsOfIP['port']:
            if 'script' in port:
                currentVulBlock[port["@portid"]]["Nmap-Vulscan"] = {}
                if type(port['script'])==list:
                    for vulscantest in port['script']:
                        currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vulscan"][vulscantest['@id']] = str(vulscantest['@output'])
                else:
                    currentVulBlock[port['@portid']]["Nmap-Vulscan"][port['script']['@id']] =  str(port['script']['@output'])
            else:
                currentVulBlock[port["@portid"]]['Nmap-Vulscan'] = noVulFound
    else:
        if 'script' in portsOfIP['port']:
            if type(portsOfIP['port']['scripts'])==list:
                for vulscantest in portsOfIP['port']['scripts']:
                    currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"] = {}
                    currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"][vulscantest['@id']] = str(vulscantest['@output'])
            else:
                currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"] = {}
                currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"][vulscantest['@id']] = str(vulscantest['@output'])

        else:
            currentVulBlock[portsOfIP['port']['@portid']]['Nmap-Vulscan'] = noVulFound

def readVulnerabilitiesNmap(pathToFile, vuln):
    with open(pathToFile) as f:
        data = json.load(f)
        hostinfo = data["nmaprun"]["host"]

        for host in hostinfo:
            for address in host["address"]:
                if 'ipv4' in address.values():
                    ip = address["@addr"]

            if vuln:
                addVulnFindingsToKey(host, ip)
            else:
                addVulscanFindingsToKey(host, ip)

def run():
    readInitialNmap('examples/multiplehosts/nmap-output.json')
    readVulnerabilitiesNmap('examples/multiplehosts/nmapvuln.json', True)   # Vuln
    readVulnerabilitiesNmap('examples/multiplehosts/nmapvuln2.json', False) # Vulscan

def save():
    with open('merger.json', 'w') as outfile:
        json.dump(out, outfile) 

def main():
    run()
    save()

if __name__ == "__main__":
    main()