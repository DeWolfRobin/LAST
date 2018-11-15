import json
import os
from argparse import ArgumentParser

parser = ArgumentParser()
masterJSON = ""
args = object

def setMasterJSON():
    global masterJSON
    with open('../output/master.json') as f:
        masterJSON = json.load(f)

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, 'r')  # return an open file handle

def updateMasterJSON(file):
    with open(file) as f:
        data = json.load(f)
        print(data)

def save():
    with open('../output/master.json', 'w') as outfile:
        json.dump(masterJSON, outfile) 

def main():
    global args
    setMasterJSON()

    parser.add_argument("-f", "--file", dest="filename", 
                        help="json file to add to the master.json",
                        metavar="FILE",
                        required=True,
                        type=lambda x: is_valid_file(parser, x))
    args = parser.parse_args()

    updateMasterJSON(args.filename.name)
    save()

if __name__ == "__main__":
    main()