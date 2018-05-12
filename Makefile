main : main.c
	gcc main.c -lpcap -o main.out

run : main
	./main.out test_pcap_file.pcapng
