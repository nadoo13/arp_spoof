all : arp_send

arp_send: main.o
	g++ -g -o arp_send main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_send
	rm -f *.o

