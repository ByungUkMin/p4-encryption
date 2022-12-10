#!/usr/bin/env python

from scapy.all import *
import threading
import socket  
import time

count_packets = 0

def handle_packet(pkt):

    global count_packets
    count_packets = count_packets + 1
    #print(pkt.show())
    #print("-----  " + str(count_packets) + " th packet  -----")
    #print("packet length: {0}".format(len(pkt)))
    #print("IP header length: {0}".format(len(pkt[IP])))
    print("{0} th received packet(Raw): {1} (length={2}) ".format(count_packets, pkt['Raw'], len(pkt['Raw'])))


def _filter(pkt):
    if (IP in pkt) and (Raw in pkt):  # capture only IP and TCP packets
        return True
    return False
        
def main():
    connected = True
    TEST = 100000
    CHUNK = 1000
    executionTime = 0

    while connected:
        try:
            start_time = time.time()
            capture=sniff(prn=lambda x: handle_packet(x),lfilter=lambda x: _filter(x),count=CHUNK)
            end_time = time.time()

            intermediate_time = end_time - start_time
            executionTime = executionTime + intermediate_time

            if count_packets >=TEST:
                connected = False
        except KeyboardInterrupt:
            return None

    print("Receiver: Execution Time = {0}".format(executionTime))


if __name__ == "__main__":
    main()
