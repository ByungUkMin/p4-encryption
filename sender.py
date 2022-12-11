#!/usr/bin/env python

from scapy.all import *
import threading
import socket  
import time

def main():
    """Parse command-line arguments and call client function """
    if len(sys.argv) != 3:
        sys.exit(
            "Usage: ./client.py [Server IP] [Server Port]")
    server_ip = sys.argv[1]
    dst_port = int(sys.argv[2])
    my_sport = random.randrange(0, 2**16)
    
    dip = IP(dst=server_ip)

    # 16byte
    payload = "Hello12345678901"
    count_packets = 0
    CHUNK = 1000
    
    start_time = time.time()
    while True:
        try:
            count_packets = count_packets + 1
            send_packet = dip/TCP(sport=my_sport, dport=dst_port)/ Raw(load=payload)
            #print(send_packet.show())
            #print("----------  " + str(count_packets) + " th packet  ---------")
            #print("packet length: {0}".format(len(send_packet)))
            #print("IP header length: {0}".format(len(send_packet[IP])))
            #print("TCP header length: {0}".format(len(send_packet['TCP'])))
            #print("Raw length: {0}".format(len(send_packet['Raw'])))
            #print("Sent packet: {0}".format(send_packet['Raw']))
            #print("-------------------")

            print("{0} th sent packet(Raw): {1} (length={2}) ".format(count_packets, send_packet['Raw'], len(send_packet['Raw'])))
            send(send_packet, count=CHUNK)
        except KeyboardInterrupt:
            return None

    end_time = time.time()
    executionTime = end_time - start_time
    #print("END: Execution Time = {0}".format(executionTime))
    print("End of the transmission from sender")

if __name__ == "__main__":
    main()
