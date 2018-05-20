main : main.c
	gcc main.c -lpcap -o main.out

run : main
	./main.out overlappingv2.pcapng
