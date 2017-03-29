CC=gcc
CFLAGS=-Wall -Wextra -c -g
all: server client

server: server.o
	$(CC) -o server server.c

client: client.o
	$(CC) -o client client.c

server.o: server.c
	$(CC) $(CFLAGS) -o server.o server.c

client.o: client.c
	$(CC) $(CFLAGS) -o client.o client.c

clean:
	rm server client *.o
