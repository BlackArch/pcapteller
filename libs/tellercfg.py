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


import os, sys, re, ipcalc, subprocess, tellerout


def check_file_exists(filename):
    return os.path.exists(filename) and os.path.isfile(filename)


def check_mac_address(mac):
    return re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())
    

def check_ip_address(ip):
    legal = False
    try:
        subnet = ipcalc.Network(ip)
        legal = True

    except ValueError:
        legal = False

    return legal


def check_network_interface(interface):
    cmd = "ifconfig -a"
    output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
    result = output.find(interface)

    return result > -1
    
    
# Mandatory args validation
def validate_mandatory_args(pcap_file, net_interface):
    if not pcap_file or not check_file_exists(pcap_file):
        tellerout.print_error("A valid pcap file must be provided.\n")
        sys.exit(1)
    
    if not net_interface or not check_network_interface(net_interface):        
        tellerout.print_error("A valid network interface must be provided.\n")
        sys.exit(1)


# Optional args validation
def validate_optional_args(pcap_mac_addr_list, wire_mac_addr_list, pcap_ip_addr_list, wire_ip_addr_list):
    if (pcap_mac_addr_list and not wire_mac_addr_list) or (wire_mac_addr_list and not pcap_mac_addr_list):
        tellerout.print_error("Lists of matching pcap and wire MAC addresses must be provided.\n")
        sys.exit(1)
        
    if (pcap_ip_addr_list and not wire_ip_addr_list) or (wire_ip_addr_list and not pcap_ip_addr_list):
        tellerout.print_error("Lists of matching pcap and wire IP addresses must be provided.\n")
        sys.exit(1)
    
    if pcap_mac_addr_list and wire_mac_addr_list:
        if len(pcap_mac_addr_list) != len(wire_mac_addr_list):
            tellerout.print_error("Pcap and wire MAC address lists must have the same number of elements.\n")
            sys.exit(1)
             
        for pcap_mac_addr in pcap_mac_addr_list:
            if not check_mac_address(pcap_mac_addr):
                tellerout.print_error("Pcap MAC address \"%s\" is not valid.\n" % (pcap_mac_addr))
                sys.exit(1)
    
        for wire_mac_addr in wire_mac_addr_list:
            if not check_mac_address(wire_mac_addr):
                tellerout.print_error("Wire MAC address \"%s\" is not valid.\n" % (wire_mac_addr))
                sys.exit(1)
        
    if pcap_ip_addr_list and wire_ip_addr_list:
        if len(pcap_ip_addr_list) != len(wire_ip_addr_list):
            tellerout.print_error("Pcap and wire IP address lists must have the same number of elements.\n")
            sys.exit(1)
        
        for pcap_ip_addr in pcap_ip_addr_list:
            if not check_ip_address(pcap_ip_addr):
                tellerout.print_error("Pcap IP address \"%s\" is not valid.\n" % (pcap_ip_addr))
                sys.exit(1)
            
        for wire_ip_addr in wire_ip_addr_list:
            if not check_ip_address(wire_ip_addr):
                tellerout.print_error("Wire IP address \"%s\" is not valid.\n" % (wire_ip_addr))
                sys.exit(1)

