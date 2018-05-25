all: ldev open.out

# LDEV - IMPORT LIBPCAP
ldev: ldev.out
	./ldev.out

ldev.out: ldev.c
	gcc ldev.c -o ldev.out -lpcap

# OPEN.OUT - OPEN & PROCESS A PCAP FILE
open.out: open_file.cpp
	g++ open_file.cpp -o open.out -lpcap

# RUN
#run: ldev
#	./ldev.out
