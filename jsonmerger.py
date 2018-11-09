import json
from pprint import pprint

out = {}
# filterWords = ["failed", "TIMEOUT", "Couldn't find", "FourOhFourRequest"]
# allowedFilteredWords = ["VULNERABLE"]
hosts = []
vulnerabilities = {}

def readInitialNmap(pathToFile):
    with open(pathToFile) as f:
        data = json.load(f)
        hostinfo = data["nmaprun"]["host"]

        for host in hostinfo:
            for address in host["address"]:
                if 'ipv4' in address.values():
                    ipadres=address["@addr"]
                    hosts.append(ipadres)
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

def deleteJSONKeyNode(currentBlock, node):
    try:
        del currentBlock['Vulnerabilities'][node]
    except KeyError:
        pass

def addVulnSingleScriptInFile(currentBlock, portsOfIP):
    currentBlock['Vulnerabilities'][portsOfIP['port']['@portid']] = {}
    port = portsOfIP['port']
    if 'script' in port:
        if type(port['script'])==list:
            for vultest in port['script']:
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
                currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][vultest['@id']] = str(vultest['@output'])
                if not str(vultest["@output"]) in vulnerabilities:
                    vulnerabilities[str(vultest["@output"])] = 1
                else:
                    vulnerabilities[str(vultest["@output"])] += 1
        else:
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] = str(port['script']['@output'])
            if not str(port['script']["@output"]) in vulnerabilities:
                vulnerabilities[str(port['script']["@output"])] = 1
            else:
                vulnerabilities[str(port['script']["@output"])] += 1
    else:
        deleteJSONKeyNode(currentBlock, port['@portid'])

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
                        if not str(vultest["@output"]) in vulnerabilities:
                            vulnerabilities[str(vultest["@output"])] = 1
                        else:
                            vulnerabilities[str(vultest["@output"])] += 1
                else:
                    currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] =  str(port['script']['@output'])
                    if not str(port['script']["@output"]) in vulnerabilities:
                        vulnerabilities[str(port['script']["@output"])] = 1
                    else:
                        vulnerabilities[str(port['script']["@output"])] += 1
            else:
                deleteJSONKeyNode(currentBlock, port['@portid'])
    else:
        addVulnSingleScriptInFile(currentBlock, portsOfIP)

def readVulnerabilitiesNmap(pathToFile):
    with open(pathToFile) as f:
        data = json.load(f)
        hostinfo = data["nmaprun"]["host"]

        for host in hostinfo:
            for address in host["address"]:
                if 'ipv4' in address.values():
                    ip = address["@addr"]

            addVulnFindingsToKey(host, ip)

def readNessus(pathToFile):
    with open(pathToFile) as f:
        data = json.load(f)
        # do something with the data!!!
    
def checkAmountOfActualVulnerabilities():
    # do smthng
    return 1

def createSummary():
    global out
    newOut = {}
    newOut["Summary"] = {}
    newOut["Summary"]["Amount of Hosts"] = len(hosts)   
    newOut["Summary"]["Vulnerabilities found"] = checkAmountOfActualVulnerabilities()

    newOut["Details"] = out
    
    out = newOut

def run():
    readInitialNmap('examples/multiplehosts/nmap-output.json')
    readVulnerabilitiesNmap('examples/multiplehosts/nmapvuln.json')   # Vuln
    #readNessus('examples/multiplehosts/nessus-output.json') # Nessus
    createSummary()

def save():
    with open('merger.json', 'w') as outfile:
        json.dump(out, outfile) 

def main():
    run()
    save()

if __name__ == "__main__":
    main()