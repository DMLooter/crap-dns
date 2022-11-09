CC = gcc
CFLAGS = -g -Wall
TARGET = dns
LIBS = -pthread

HEADERS = dns.h
OBJECTS = dns.o server.o

default: $(TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LIBS) $(OBJECTS) -o $@

clean:
	rm -f *.o
	rm -f $(TARGET)

