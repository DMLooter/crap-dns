clean:
	rm dns

build:
	gcc -g dns.c dns.h -o dns
