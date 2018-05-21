#Makefile - compile our program - example : "make run"  in your terminal
main : main.c header.h
			gcc main.c -lpcap -o main.out


run : main
			./main.out overlappingv2.pcapng

clean :
			rm main.out
