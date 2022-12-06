#!/usr/bin/env python

from scapy.all import *
import threading
import socket  

SEND_PACKET_SIZE = 1000  # should be less than max packet size of 1500 bytes

# A client class for implementing TCP's three-way-handshake connection establishment and closing protocol,
# along with data transmission.

# Name: Franklin Liu
# PUID: liu2194
#


def main():
    """Parse command-line arguments and call client function """
    if len(sys.argv) != 3:
        sys.exit(
            "Usage: ./client-3wh.py [Server IP] [Server Port] < [message]")
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    my_sport = random.randrange(0, 2**16)
    
    dip = IP(dst=server_ip)
    
    payload = "HelloWorldaaaaaa" # 16byte
    
    #send_packet = dip/ICMP()/ Raw(load=payload)
    send_packet = dip/TCP(sport=my_sport, dport=server_port)/ Raw(load=payload)

    send(send_packet, count = 10000)


if __name__ == "__main__":
    main()
