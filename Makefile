CC = gcc
CFLAGS = -Wall
DEPS = utils.h
LIBS = -lpcap
OBJ = main.o utils.o

all: main

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

main: $(OBJ)
	$(CC) $(CFLAGS) -o p2a $^ $(LIBS)
