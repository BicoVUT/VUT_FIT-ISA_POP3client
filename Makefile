
# author: Filip Brna, xbrnaf00
# Projekt: ISA Klient POP3 s podporou TLS

CC=g++
CFLAGS=-std=c++17 
LDLIBS = -lssl -lcrypto -pthread -lpthread -ldl


all:
	$(CC) $(CFLAGS)  popcl.cpp -o popcl  $(LDFLAGS) $(LDLIBS)
