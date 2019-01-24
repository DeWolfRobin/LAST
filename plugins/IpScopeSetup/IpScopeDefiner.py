#File inscope en outscope worden aangemaakt door dit script
#vragen zijn hardcoded
#Gebruik python3 !!!!!!!

##Imports
import socket
from optparse import OptionParser

##Global variables

#Questions strings, stored her for easy changes and translations
questions = [
        "Wat is de start van de IPScope?: ",
        "Wat is het einde van de IPScope?: ",
        "Zijn er IP's die niet in de scope zitten, y/n?: ",
        "Geef de IP's die niet in de scope zitten? Duw enter om te stoppen",
        "Het gegeven IP is niet geldig, geeft een geldig IP:"
            ]

#Dictionary for the range (startIp, endIp)
inScopeRange = {}

#Array for IP's out of scope
outScopeIp = []


##Fuctions

#Check if command line input was given
def checkCommandOptions(rangeOption, outScopeOption):
    if(rangeOption != None): parseRangeOption(rangeOption)
    else: askScopeQuestions()
    if(outScopeOption != None): parseOutScopeOption(outScopeOption)
    else: askNotInScopeIp()


def parseRangeOption(rangeInput):
    rangeList = rangeInput.split("-")
    isValidInput = False
    for ip in rangeList:
        isValidInput =validate(ip)
    if not isValidInput:
        print("Invalid! IP given ")
        askScopeQuestions()
    else:
        inScopeRange["startIp"] = rangeList[0]
        inScopeRange["endIp"] = rangeList[1]


def parseOutScopeOption(outScopeInput):
    outIpList = outScopeInput.split(",")
    isValidInput = False
    for ip in outIpList:
        isValidInput =validate(ip)
        if(isValidInput): outScopeIp.append(ip)
        else: print(ip + " is not valid, this will not be added to the list")



#Asks the Questions (What is the inscope range and the out)
def askScopeQuestions():
        askIpScopeQuestion("startIp", questions[0])
        checkEndIpAfterbegin("endIp", questions[1])



#Fuction to ask the inscope range, rangeLabel is start or end question is from
#the array above. Sets Dictionary and also validates provided IP
def askIpScopeQuestion(rangeLable, inputQuestion):
    inScopeRange[rangeLable] =  checkInputIpValid(input(inputQuestion))

#Asks if there are outscope IP's and if so fills the array with valid IP's
def askNotInScopeIp():
    if  str(input(questions[2])).lower() == "y":
        print(questions[3])
        ip = input("[-] ")
        while(ip != ""):
            if validate(ip) and isIpInRange(ip): outScopeIp.append(ip)
            else:  print("Invalid IP")
            ip = input("[-] ")

#validates IP and keeps asking until it gets a valid IP
def checkInputIpValid(ip):
    while not validate(ip):
        ip = input(questions[4])
    return ip

#IP validate function, has some issues like 1.2.3.4 is valid but should it?
def validate(ipToValidate):
    try:
        socket.inet_aton(ipToValidate)
    except socket.error:
        return False
    return ipToValidate.count('.') == 3

#Get the end ip of the scope and check if it is after the first one
def checkEndIpAfterbegin(rangeLable, inputQuestion):
    ip = checkInputIpValid(input(inputQuestion))
    while not isIpAfterIp(ip):
        print("Error: End IP is lager dan het start IP")
        ip = checkInputIpValid(input(inputQuestion))
    inScopeRange[rangeLable] =  ip

#the name says it all
def isIpAfterIp(endIp):
    return convertIpToList(endIp) > convertIpToList(inScopeRange["startIp"])

#Check if ip is between startIp and endIp
def isIpInRange(ip):
    startIp = convertIpToList(inScopeRange["startIp"])
    endIp = convertIpToList(inScopeRange["endIp"])
    betweenIp = convertIpToList(ip)
    if not endIp > betweenIp > startIp:
        print("Error: IP zit niet in de gegeven range")
        return  False
    return True

def convertIpToList(ip):
    return list(map(int, ip.split('.') ))

#Write all the variables to the appropriate files
def writeToFiles():
    writeToFile("inscope.txt",inScopeRange)
    writeToFile("outscope.txt",outScopeIp )

#Creates a file with the provide name and variable
def writeToFile(fileName, attrToWrite):
    inScope = open(fileName, "w+")
    inScope.write(str(attrToWrite))
    inScope.close()


#Main function, define parser and then check invoke the other fuctions
def main():
    parser = OptionParser('usage %prog -s <Scope startIp-endIp> -o <outScopeIp sperarated by ,> ')
    parser.add_option('-s', dest = 'range', type = 'string', help = '')
    parser.add_option('-o', dest = 'out', type = 'string', help = '')
    (options, args) = parser.parse_args()

    checkCommandOptions(options.range, options.out)
    writeToFiles()

#Main
if __name__ == "__main__":
    main()
