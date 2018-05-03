all: ldev

ldev: ldev.c
	gcc ldev.c -o ldev.out -lpcap

run: ldev
	./ldev.out
