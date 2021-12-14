all: tcp-block

tcp-block: tcp-block.o main.o
	g++ -o tcp-block tcp-block.o main.o -lpcap

main.o: header.h tcp-block.h main.cpp 
	g++ -c main.cpp header.h tcp-block.h 
tcp-block.o: header.h tcp-block.h tcp-block.cpp
	g++ -c tcp-block.cpp header.h tcp-block.h

clean:
	rm -f tcp-block
	rm -f *.o
