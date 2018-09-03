CC = gcc
CFLAGS = -Wall
DEPS = utils.h
LIBS = -lpcap -lcrypto
OBJ = main.o utils.o

all: main

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

main: $(OBJ)
	$(CC) $(CFLAGS) -o p2a $^ $(LIBS)

sha: sha.o
	$(CC) $(CFLAGS) -o sha $^ $(LIBS)
