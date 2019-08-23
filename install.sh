#!/bin/sh

clear
echo " ================================================================= "
echo "|  Pcapteller - Install Script                                    |"
echo "|  by Juan J. Guelfo, Encripto AS (post@encripto.no)              |"
echo " ================================================================= "

echo "\n\n\033[1;34m[*]\033[1;m Installing dependencies (python-scapy & python-ipcalc)...\n"
sleep 2
sudo apt-get update && sudo apt-get install -y python-scapy python-ipcalc

echo "\n\033[1;32m[+]\033[1;m Installation completed!\n"