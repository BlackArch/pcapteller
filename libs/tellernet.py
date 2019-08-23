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

import sys, httplib, tellerout

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def check_for_updates(version):
    try:
        http_conn = httplib.HTTPSConnection("www.encripto.no", 443, timeout=10)
        headers = { "User-Agent" : "Mozilla/5.0 (compatible; Pcapteller/" + version + ")"}
        http_conn.request("HEAD", "/tools/pcapteller-" + version + ".tar.gz", None, headers)
        http_resp = http_conn.getresponse()

        if http_resp.status == 404:
            tellerout.print_ok("There is a new version of Pcapteller!")
            tellerout.print_ok("Check https://www.encripto.no/tools for more information.\n")

        elif http_resp.status == 200:
            tellerout.print_info("You are running the latest version of Pcapteller.\n")

        else:
            tellerout.print_warning("Could not check for updates...\n")

        http_conn.close()

    except:
        tellerout.print_warning("Could not check for updates...\n")

    return


def read_traffic(pcap_file):
    return rdpcap(pcap_file)
    

def traffic_manipulation(pcap_file, total_packets, pcap_mac_addr_list, wire_mac_addr_list, pcap_ip_addr_list, wire_ip_addr_list):
    packet_counter = 0
    error_counter = 0
    packets = []
    for packet in pcap_file:
        try:
            packet_counter += 1
            sys.stdout.write("\r\033[1;34m[*]\033[1;m Processing %s of %s packet(s) | Error: %s packet(s)." % (packet_counter, total_packets, error_counter))
            sys.stdout.flush()
            
            if packet.haslayer(Ether):
                del(packet[Ether].chksum)
                if pcap_mac_addr_list and wire_mac_addr_list:
                    for pcap_mac_addr, wire_mac_addr in zip(pcap_mac_addr_list, wire_mac_addr_list):
                        if packet[Ether].src == pcap_mac_addr:
                            packet[Ether].src = wire_mac_addr

                        elif packet[Ether].dst == pcap_mac_addr:
                            packet[Ether].dst = wire_mac_addr

            if packet.haslayer(UDP):
                del(packet[UDP].chksum)

            if packet.haslayer(ICMP):
                del(packet[ICMP].chksum)

            if packet.haslayer(TCP):
                del(packet[TCP].chksum)

            if packet.haslayer(IP):
                del(packet[IP].chksum)
                if pcap_ip_addr_list and wire_ip_addr_list:
                    for pcap_ip_addr, wire_ip_addr in zip(pcap_ip_addr_list, wire_ip_addr_list):
                        if packet[IP].src == pcap_ip_addr:
                            packet[IP].src = wire_ip_addr

                        elif packet[IP].dst == pcap_ip_addr:
                            packet[IP].dst = wire_ip_addr
                    
            packets.append(packet)

        except:
            error_counter += 1
    
    return packets


def traffic_replay(packets, net_interface, real_time):
    error = False
    try:
        sendp(packets, iface=net_interface, verbose=0, realtime=real_time)

    except:
        error = True
        
    return error
