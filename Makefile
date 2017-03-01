#
# Makefile for 2nd round of interview in AVG
# Jakub J. Šimon, 9th August 2013
#
#Name of the translates executable
executable=peparse

#List of files
OBJ=reads.o writes.o main.o

#Compiler name
CC=g++

#Flags
CFLAGS=-std=c++11 -Wall -pedantic -Wno-long-long -O0

#compilation

compile: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(executable)

$(executable): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(executable)

writes.o: writes.cpp
	$(CC) $(CFLAGS) -c writes.cpp
reads.o: reads.cpp 
	$(CC) $(CFLAGS) -c reads.cpp 
main.o: main.cpp 
	$(CC) $(CFLAGS) -c main.cpp

clean:
	rm *.o
	rm $(executable)

install: $(executable)
	cp $(executable) /usr/bin

uninstall:
	rm /usr/bin/$(executable)
