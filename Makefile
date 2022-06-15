CC = g++

CLFLAGS  = -g -Wall

popcl : parser.o main.o
	$(CC) $(CFLAGS) -I /usr/local/ssl/include -lssl -lcrypto -o popcl parser.o main.o

main.o : main.cpp
	$(CC) $(CFLAGS) -c -o main.o main.cpp

parser.o : parser.cpp parser.hpp
	$(CC) $(CFLAGS) -c -o parser.o parser.cpp

clean:
	rm *.o popcl
