# L.A.S.T.
## Linux Automated Security scanning Tool
> the LAST tool you will ever use!

This tool is used to automate the recon proces of Red Team Excercises. It gathers all the information and reports it back in an easy to read format. The script is made so it is possible for everyone to include his own plugins and addons.

## Usage
### Installation
1. run `install.sh`
1. manually install nessus, run it by entering `/etc/init.d/nessusd start`, then activate it and create a user account.
1. generate api keys and place them inside the `config/apikey.conf` like this: `accessKey=X;secretKey=X`.
1. now create the `config/nmap.conf` (see below)
1. **create a policy for your nessus scans, this is required!**
> Nessus will be started automatically when needed by the script

### LAST.sh
You can just run this script on any linux system like `./last.sh` or `sh last.sh`

### Config
#### Scope (Required)
##### nmap.conf
Here you can define the IP addresses to be scanned.
Supported notations:
- newline seperated
- comma seperated
- 0.0.0.0/24
- [0-255]*.*[0-255]*.*[0-255]*.*[0.255]

##### apikey.conf
This conf file contains your nessus api keys in the form of: `accessKey=X;secretKey=X`
Replace the X's with your corresponding keys.

## createMasterJson.py
Integrated in *LAST.sh*.

Run this tool to convert the output we got from Nessus & nmap to create one summary JSON file.
The output json follows the following structure:
- { Summary: {'amount of hosts': number, 'vulnerabilities': {} }, Details: { 'ipadresses': {} } }

## mergeNewJson.py
If you have your own plugin and want to add any found data to the master.json file.
- python mergeNewJson.py -f file.json

> Note: the -f parameter is required, it has to be a json from a valid structure

The valid structure is:
- { X.X.X.X: { key: value } }

The main Key should be an IP-Address, with a json as value.
You can create any keyname but if you have vulnerabilities, add a Vulnerabilities key with json value.

Example:
- { X.X.X.X: { key: value, "Vulnerabilities": { key:value} } }

## Creators
- [Brian Dendauw](https://github.com/DendauwBrian)
- [Quinten Bombeke](https://github.com/BombekeQuinten)
- [Robin De Wolf](https://github.com/DeWolfRobin)
- [Shan Rizvi](https://github.com/OneTrueKill)

## Special Thanks
### All the creators of the tools we use (located in the plugins folder)
