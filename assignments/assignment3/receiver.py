#!/usr/bin/env python

from scapy.all import *
import threading
import socket  

SEND_PACKET_SIZE = 1000  # should be less than max packet size of 1500 bytes

count_packets = 0

# A client class for implementing TCP's three-way-handshake connection establishment and closing protocol,
# along with data transmission.

# Name: Franklin Liu
# PUID: liu2194
#
            
def handle_packet(pkt):
    """TODO(1): Handle incoming packets from the server and acknowledge them accordingly. Here are some pointers on
       what you need to do:
       1. If the incoming packet has data (or payload), send an acknowledgement (TCP) packet with correct 
          `sequence` and `acknowledgement` numbers.
       2. If the incoming packet is a FIN (or FINACK) packet, send an appropriate acknowledgement or FINACK packet
          to the server with correct `sequence` and `acknowledgement` numbers.
    """

    print(str(pkt['Raw']))
    
    global count_packets
    count_packets = count_packets + 1

def _filter(pkt):
    if (IP in pkt) and (Raw in pkt):  # capture only IP and TCP packets
        return True
    return False
        
def main():
    """Parse command-line arguments and call client function """
    connected = True
    while connected:
        capture=sniff(prn=lambda x: handle_packet(x),lfilter=lambda x: _filter(x),count=1)
        if count_packets >=50:
            connected = False


if __name__ == "__main__":
    main()
