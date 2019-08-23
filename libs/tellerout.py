#!/usr/bin/python

################################################################
#                                                              #
# Pcapteller - A packet manipulation & replay tool             #
# written by Juan J. Guelfo @ Encripto AS                      #
# post@encripto.no                                             #
#                                                              #
# Copyright 2015-2016 Encripto AS. All rights reserved.        #
#                                                              #
# Pcapteller is licensed under the FreeBSD license.            #
# http://www.freebsd.org/copyright/freebsd-license.html        #
#                                                              #
################################################################

import os, sys

FILE_NOT_FOUND = "File cannot be found"


def print_ok(msg):
    print "\033[1;32m[+]\033[1;m {0}".format(msg)


def print_warning(msg):
    print "\033[1;33m[!]\033[1;m {0}".format(msg)

def print_error(msg):
    print "\033[1;31m[-]\033[1;m {0}".format(msg)


def print_info(msg):
    print "\033[1;34m[*]\033[1;m {0}".format(msg)


def print_title(msg):
    print "\033[1;37m{0}\033[1;m".format(msg)


def print_header(version, author):
    os.system("clear")

    print ""
    print " ================================================================= "
    print "|  Pcapteller v{0}: A packet manipulation & replay tool\t\t  |".format(version)
    print "|  by {0}\t\t  |".format(author)
    print " ================================================================= "
    print ""


def help(version, author):
    print_header(version, author)
    print """   Usage: python pcapteller.py [mandatory args] [optional args]

   Mandatory args:
       -f  file         ...Pcap file to replay in libpcap format.
       -i  interface    ...Network interface to replay the packets with.
   
   Optional args:
       -a  MAC addr     ...List of MAC addresses to replace as seen on the pcap file.
       -b  MAC addr     ...List of MAC addresses to replay as seen on the wire.
       
       -c  IP addr      ...List of IP addresses to replace as seen on the pcap file.
       -d  IP addr      ...List of IP addresses to replay as seen on the wire.
       
       -r               ...Honor inter-arrival delays while replaying packets.
       -u               ...Check for software updates at startup.

   Examples:
       
       1. Replay a pcap file as it is (full speed): 
          python pcapteller.py -f example.pcap -i eth0
          
       2. Replay a pcap file as it is (inter-arrival delays): 
          python pcapteller.py -f example.pcap -i eth0 -r
       
       3. Replay a pcap file and replace a single MAC address:
          python pcapteller.py -f example.pcap -i eth0 -a 00:01:02:03:04:05 -b 00:DE:AD:BE:EF:00
       
       4. Replay a pcap file and replace a single IP address:
          python pcapteller.py -f example.pcap -i eth0 -c 192.168.1.2 -d 10.20.30.40
       
       5. Replay a pcap file and replace a single MAC / IP address:
          python pcapteller.py -f example.pcap -i eth0 -a 00:01:02:03:04:05 -b 00:DE:AD:BE:EF:00 -c 192.168.1.2 -d 10.20.30.40
          
       6. Replay a pcap file and replace multiple MAC addresses:
          python pcapteller.py -f example.pcap -i eth0 -a "00:01:02:03:04:05, 00:AA:BB:CC:DD:EE" -b "00:DE:AD:BE:EF:00, 00:C0:FF:EE:BA:BE"
          
       7. Replay a pcap file and replace multiple IP addresses:
          python pcapteller.py -f example.pcap -i eth0 -c "192.168.1.2, 192.168.1.3" -d "10.20.30.40, 50.60.70.80"
          
       8. Replay a pcap file and replace multiple MAC / IP addresses:
          python pcapteller.py -f example.pcap -i eth0 -a "00:01:02:03:04:05, 00:AA:BB:CC:DD:EE" -b "00:DE:AD:BE:EF:00, 00:C0:FF:EE:BA:BE" -c "192.168.1.2, 192.168.1.3" -d "10.20.30.40, 50.60.70.80"

       Pcapteller requires root (or sudo) privileges in order to replay packets successfully.
    """
    sys.exit(0)
