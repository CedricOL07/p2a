main : main.c
	gcc main.c -lpcap

run : main
	./a.out test_pcap_file.pcapng
