import json
from pprint import pprint

out = {}
# filterWords = ["failed", "TIMEOUT", "Couldn't find", "FourOhFourRequest"]
# allowedFilteredWords = ["VULNERABLE"]
noVulFound = "None found"
vulscanErrorOK = "scip VulDB - http://www.scip.ch/en/?vuldb:\nNo findings\n\nMITRE CVE - http://cve.mitre.org:\nNo findings\n\nOSVDB - http://www.osvdb.org:\nNo findings\n\nSecurityFocus - http://www.securityfocus.com/bid/:\nNo findings\n\nSecurityTracker - http://www.securitytracker.com:\nNo findings\n\nIBM X-Force - http://xforce.iss.net:\nNo findings\n\nExploit-DB - http://www.exploit-db.com:\nNo findings\n\nOpenVAS (Nessus) - http://www.openvas.org:\nNo findings\n\n"

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
                currentport = host["ports"]["port"]["@portid"]
                out[ipadres]['Ports'][currentport] = {}
                out[ipadres]['Ports'][currentport]['protocol'] = host["ports"]["port"]["@protocol"]
                out[ipadres]['Ports'][currentport]['service'] = host["ports"]["port"]["service"]["@name"]

def deleteJSONKeyNode(node):
    try:
        del node
    except KeyError:
        pass

def addVulnSingleScriptInFile(currentBlock, portsOfIP):
    # Create a key for the port
    currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']] = {}
    port = portsOfIP['port']
    if 'script' in port:
        if type(port['script'])==list:
            for vultest in port['script']:
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][vultest['@id']] = str(vultest['@output'])
        else:
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] = str(port['script']['@output'])
    else:
        deleteJSONKeyNode(currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']])
        # currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']]["Nmap-Vuln"] = noVulFound

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
                deleteJSONKeyNode(currentBlock['Vulnerabilities'][port['@portid']])
                # currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = noVulFound
    else:
        addVulnSingleScriptInFile(currentBlock, portsOfIP)

def addVulscanFindingsToKey(arg, ip):
    currentBlock = out[ip]
    portsOfIP = arg['ports']
    currentVulBlock = currentBlock['Vulnerabilities']
    canDelete = False
    nodeExists = False

    # Check if there is >1 port on the system
    if type(portsOfIP['port'])==list:
        for port in portsOfIP['port']:
            # Make the key of the portID if it doesn't exist
            if not port['@portid'] in currentVulBlock:
                nodeExists = True
                currentVulBlock[port['@portid']] = {}
            
            # Check if there have been any scripts executed on the port
            if 'script' in port:
                currentVulBlock[port["@portid"]]["Nmap-Vulscan"] = {}

                #Check if there have been >1 script executed
                if type(port['script'])==list:
                    for vulscantest in port['script']:
                        if str(vulscantest["@output"]).__eq__(vulscanErrorOK):
                            canDelete = True
                        else:
                            canDelete = False
                            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vulscan"][vulscantest['@id']] = str(vulscantest['@output'])
                else:
                    if str(port['script']["@output"]).__eq__(vulscanErrorOK):
                        canDelete = True
                    else:
                        canDelete = False
                        currentVulBlock[port['@portid']]["Nmap-Vulscan"][port['script']['@id']] =  str(port['script']['@output'])

            if canDelete and nodeExists:
                deleteJSONKeyNode(currentVulBlock[port['@portid']])
    else:
        # Make the key of the portID if it doesn't exist
        if not portsOfIP['port']['@portid'] in currentVulBlock:
            nodeExists = True
            currentVulBlock[portsOfIP['port']['@portid']] = {}

        if 'script' in portsOfIP['port']:
            if type(portsOfIP['port']['script'])==list:
                for vulscantest in portsOfIP['port']['script']:
                    if str(vulscantest["@output"]).__eq__(vulscanErrorOK):
                        canDelete = True
                    else:
                        canDelete = False
                        currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"] = {}
                        currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"][vulscantest['@id']] = str(vulscantest['@output'])
            else:
                if str(portsOfIP['port']['script']["@output"]).__eq__(vulscanErrorOK):
                    canDelete = True
                else:
                    canDelete = False
                    currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"] = {}
                    currentVulBlock[portsOfIP['port']]["@portid"]["Nmap-Vulscan"][portsOfIP['port']['script']['@id']] = str(portsOfIP['port']['script']['@output'])
        
        if canDelete and nodeExists:
            deleteJSONKeyNode(currentVulBlock[portsOfIP['script']['@portid']])

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

def readNessus(pathToFile):
    with open(pathToFile) as f:
        data = json.load(f)
        # do something with the data!!!

def run():
    readInitialNmap('examples/multiplehosts/nmap-output.json')
    readVulnerabilitiesNmap('examples/multiplehosts/nmapvuln.json', True)   # Vuln
    readVulnerabilitiesNmap('examples/multiplehosts/nmapvuln2.json', False) # Vulscan
    readNessus('examples/multiplehosts/nessus-output.json') # Nessus

def save():
    with open('merger.json', 'w') as outfile:
        json.dump(out, outfile) 

def main():
    run()
    save()

if __name__ == "__main__":
    main()