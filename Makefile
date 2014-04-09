traffana: traffana.o
	gcc -o traffana -g -Wall traffana.o -lpcap

traffana.o: traffana.c traffana.h
	gcc -g -c -Wall traffana.c -lpcap

clean:
	rm -f *.o traffana
