#!/usr/bin/env bash

# $domain should come from masterscript (maybe in scope
dnscan(){
  dnsrecon -d $1 -D /usr/share/wordlists/dnsmap.txt -t axfr -j $(pwd)/dnsinfo.json
}
dnscan 'localhost'
