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


import sys, getopt, datetime
import libs.tellerout, libs.tellercfg, libs.tellernet


__version__ = "1.1"
__author__ = "Juan J. Guelfo, Encripto AS (post@encripto.no)"


if __name__ == '__main__':

    try:
        options, args = getopt.getopt(sys.argv[1:], "f:i:a:b:c:d:ru")

    except getopt.GetoptError, e:
        libs.tellerout.print_header(__version__, __author__)
        libs.tellerout.print_error("ERROR: %s.\n" % (e))
        sys.exit(1)

    if not options:
        libs.tellerout.help(__version__, __author__)

    pcap_file     = None
    net_interface = None
    real_time     = False
    check_updates = False
    
    pcap_mac_addr_list = None
    pcap_ip_addr_list  = None
    
    wire_mac_addr_list = None
    wire_ip_addr_list  = None

    for opt, arg in options:
        if opt in ("-r"):
            real_time = True
            
        if opt in ("-u"):
            check_updates = True
            
        if opt in ("-f"):
            pcap_file = arg.replace("\n", "").replace(" ", "")

        if opt in ("-i"):
            net_interface = arg.replace("\n", "").replace(" ", "")

        if opt in ("-a"):
            pcap_mac_addr_list = arg.replace("\n", "").replace(" ", "").split(",")
            
        if opt in ("-b"):
            wire_mac_addr_list = arg.replace("\n", "").replace(" ", "").split(",")
               
        if opt in ("-c"):
            pcap_ip_addr_list = arg.replace("\n", "").replace(" ", "").split(",")        
            
        if opt in ("-d"):
            wire_ip_addr_list = arg.replace("\n", "").replace(" ", "").split(",")

    try:
        # Print banner and input validation
        libs.tellerout.print_header(__version__, __author__)        
        libs.tellercfg.validate_mandatory_args(pcap_file, net_interface)
        libs.tellercfg.validate_optional_args(pcap_mac_addr_list, wire_mac_addr_list, pcap_ip_addr_list, wire_ip_addr_list)
     
        # Check for updates and preliminary PCAP file processing
        if check_updates:
            libs.tellernet.check_for_updates(__version__)
            
        libs.tellerout.print_info("Reading pcap file...")
        pf = libs.tellernet.read_traffic(pcap_file)

        total_packets = len(pf)
        libs.tellerout.print_ok("%s packet(s) found.\n" % (total_packets))
        libs.tellerout.print_info("Starting replay at %s...\n" % (datetime.datetime.now().strftime("%H:%M:%S")))

        # Traffic manipulation
        packets = libs.tellernet.traffic_manipulation(pf, total_packets, pcap_mac_addr_list, wire_mac_addr_list, pcap_ip_addr_list, wire_ip_addr_list)
        print ""

        # Traffic replay
        if real_time:
            libs.tellerout.print_warning("Real time enabled. Replay speed will be determined by the actual pcap file...")
            
        libs.tellerout.print_info("Replaying packet(s) via %s..." % (net_interface))
        error_replay = libs.tellernet.traffic_replay(packets, net_interface, real_time)
        
        if error_replay:
            libs.tellerout.print_warning("Replay incomplete. An error ocurred during the replay.\n")

        else:    
            libs.tellerout.print_ok("Replay complete.\n")
            
        libs.tellerout.print_info("Pcapteller finished at %s.\n" % (datetime.datetime.now().strftime("%H:%M:%S")))
        sys.exit()

    except KeyboardInterrupt:
        print ""
        libs.tellerout.print_warning("CTRL+C was pressed. Shutting down...\n")
        sys.exit()

    except Exception as e:
        libs.tellerout.print_error("ERROR: %s.\n" % (e))
        sys.exit()
