# L.A.S.T.
## Linux Automated Security scanning Tool
> the LAST tool you will ever use!

This tool is used to automate the recon proces of Red Team Excercises. It gathers all the niformation and reports it back in an easy to read format. The script is made so it is possible for everyone to include his own plugins and addons.

## Usage
### Installation
To be implemented (run install.sh)

### LAST.sh
You can just run this script on any linux system like `./last.sh` or `sh last.sh`

### Config
#### Scope
nmap.conf
Here you can define the IP addresses to be scanned.
Supported notations:
- newline seperated
- comma seperated
- 0.0.0.0/24
- [0-255]*.*[0-255]*.*[0-255]*.*[0.255]

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
### All the creators of the tools we use
