import json
import os
import socket
from argparse import ArgumentParser

parser = ArgumentParser()
masterJSON = ""
args = object
pluginname = ""

def setMasterJSON():
    global masterJSON
    with open('../output/master.json') as f:
        masterJSON = json.load(f)

def isValidFile(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, 'r')  # return an open file handle

def isJsonStructureValid(data):
    isIP = True
    for ip in data:
        try:
            socket.inet_aton(ip)
        except:
            isIP = False
            print("Incoming json is wrong. The main key should be an ip-adress. You gave '" + ip + "'")
            break
        
        if ip.count('.')==3 and isIP == True:
            isIP = True
        else:
            isIP = False
            print("Incoming json is wrong. The main key should be an ip-adress. You gave '" + ip + "'")
            break  

    return isIP

def addBlockToMaster(data):
    for ip in data:
        if ip in masterJSON["Details"]:
            for key in data[ip]:
                if key == "Vulnerabilities":
                    masterJSON["Details"][ip]["Vulnerabilities"][pluginname+" "] = data[ip][key]
                else:
                    masterJSON["Details"][ip][pluginname] = {}
                    masterJSON["Details"][ip][pluginname][key] = data[ip][key]
        else:
            masterJSON["Details"][ip] = data[ip]

def updateMasterJSON(file):
    with open(file) as f:
        data = json.load(f)
        if not isJsonStructureValid(data):
            exit()
        
        addBlockToMaster(data)

def save():
    with open('../output/master.json', 'w') as outfile:
        json.dump(masterJSON, outfile) 

def setName():
    global pluginname
    pluginname = args.filename.name.split('.')[0]

def main():
    global args
    setMasterJSON()

    parser.add_argument("-f", "--file", dest="filename", 
                        help="json file to add to the master.json",
                        metavar="FILE",
                        required=True,
                        type=lambda x: isValidFile(parser, x))
    args = parser.parse_args()
    
    setName()

    updateMasterJSON(args.filename.name)
    save()

if __name__ == "__main__":
    main()