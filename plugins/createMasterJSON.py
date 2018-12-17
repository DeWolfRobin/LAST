import json
import re
from pprint import pprint

out = {}
filterWords = ["Couldn't find", "Script execution failed", "NOT VULNERABLE", "No reply from server", "TRACE"]
cvecode = "CVE:"
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

def deleteJSONKeyNode(jsonblock, node):
    try:
        del jsonblock[node]
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
                    vulnerabilities[str(vultest["@output"]).replace('\n','')] = 1
                else:
                    vulnerabilities[str(vultest["@output"]).replace('\n','')] += 1
        else:
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"] = {}
            currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] = str(port['script']['@output'])
            if not str(port['script']["@output"]) in vulnerabilities:
                vulnerabilities[str(port['script']["@output"]).replace('\n','')] = 1
            else:
                vulnerabilities[str(port['script']["@output"]).replace('\n','')] += 1
    else:
        deleteJSONKeyNode(currentBlock['Vulnerabilities'], port['@portid'])

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
                            vulnerabilities[str(vultest["@output"]).replace('\n','')] = 1
                        else:
                            vulnerabilities[str(vultest["@output"]).replace('\n','')] += 1
                else:
                    currentBlock['Vulnerabilities'][port['@portid']]["Nmap-Vuln"][port['script']['@id']] =  str(port['script']['@output'])
                    if not str(port['script']["@output"]) in vulnerabilities:
                        vulnerabilities[str(port['script']["@output"]).replace('\n','')] = 1
                    else:
                        vulnerabilities[str(port['script']["@output"]).replace('\n','')] += 1
            else:
                deleteJSONKeyNode(currentBlock['Vulnerabilities'], port['@portid'])
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
        report = data["NessusClientData_v2"]["Report"]

        if type(report["ReportHost"])==list:
            for host in report["ReportHost"]:
                ip = host["@name"]
                out[ip]['Vulnerabilities']["Nessus-Severity-1"] = {}
                out[ip]['Vulnerabilities']["Nessus-Severity-2"] = {}
                out[ip]['Vulnerabilities']["Nessus-Severity-3"] = {}
                out[ip]['Vulnerabilities']["Nessus-Severity-4"] = {}
                if type(host["ReportItem"])==list:
                    for item in host["ReportItem"]:
                        nessusseveritylevel = "Nessus-Severity-"+item["@severity"]
                        if not item["@severity"] == '0':
                            out[ip]['Vulnerabilities'][nessusseveritylevel][item["@pluginName"]] = item["description"]["#text"]
                else:
                    print("no")
        else:
            print("no list")
    
def checkAmountOfActualVulnerabilities():
    keysToDelete = []
    cveKeysToDelete = []

    for key in vulnerabilities:
        if not len(key) > 0:
            keysToDelete.append(key)
        if any(word in key for word in filterWords):
            keysToDelete.append(key)
        if cvecode in key:
            cveKeysToDelete.append(key)
    
    if len(cveKeysToDelete) > 0 : vulnerabilities['CVE'] = {}

    for key in cveKeysToDelete:
        beginning = key.find(cvecode)
        end = len("CVE:CVE-0000-0000000")
        newkey = key[beginning : beginning + end].split(' ')[0]
        vulnerabilities["CVE"][newkey] = vulnerabilities.pop(key)

    for key in keysToDelete:
        deleteJSONKeyNode(vulnerabilities, key)

    keysToDelete = []
    for key in vulnerabilities:
        if key is not "CVE":
            keysToDelete.append(key)

    vulnerabilities["Uncategorised"] = {}
    for key in keysToDelete:
        vulnerabilities["Uncategorised"][key] = vulnerabilities.pop(key)

def deleteNoCriticalsFound(jsonblock):
    keysToDelete = []
    criticalHosts = jsonblock
    for host in criticalHosts:
        if criticalHosts[host] == 0:
            keysToDelete.append(host)

    for key in keysToDelete:
            deleteJSONKeyNode(criticalHosts, key)

def createSummary():
    global out
    newOut = {}
    newOut["Summary"] = {}
    newOut["Summary"]["Amount of Hosts"] = len(hosts)   
    checkAmountOfActualVulnerabilities()
    newOut["Summary"]["Vulnerabilities found"] = vulnerabilities

    newOut["Summary"]["Vulnerabilities found"]["Nessus-Severity-3"] = {}
    newOut["Summary"]["Vulnerabilities found"]["Nessus-Severity-4"] = {}

    for host in hosts:
        newOut["Summary"]["Vulnerabilities found"]["Nessus-Severity-3"][host] = len(out[host]["Vulnerabilities"]["Nessus-Severity-3"])
        newOut["Summary"]["Vulnerabilities found"]["Nessus-Severity-4"][host] = len(out[host]["Vulnerabilities"]["Nessus-Severity-4"])
    
    newOut["Details"] = out
    out = newOut

def run():
    readInitialNmap('../output/nmap-output.json')
    readVulnerabilitiesNmap('../output/nmapvuln.json')
    readNessus('../output/nessus.json')
    
    createSummary()
    
    deleteNoCriticalsFound(out["Summary"]["Vulnerabilities found"]["Nessus-Severity-3"])
    deleteNoCriticalsFound(out["Summary"]["Vulnerabilities found"]["Nessus-Severity-4"])

def save():
    with open('../output/master.json', 'w') as outfile:
        json.dump(out, outfile) 

def main():
    run()
    save()

if __name__ == "__main__":
    main()
