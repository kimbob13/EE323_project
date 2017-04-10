CC = gcc
CFLAGS = -Wall -Wextra -g -std=gnu99

SOURCES = proxy.c
HEADER = proxy.h
TARGET = proxy

.PHONY: all clean tags submit

objects = $(SOURCES:.c=.o)

proxy: $(objects)
	$(CC) $(CFLAGS) -o $(TARGET) $(objects)

all: $(TARGET)

clean:
	@rm -f *.o $(TARGET)

tags:
	@ctags $(SOURCES)

submit: clean
	@tar zcf 20130184_assign2.tar.gz $(SOURCES) $(HEADER) README Makefile
