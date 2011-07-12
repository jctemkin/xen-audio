CC=gcc
LIBS=-lxenctrl -lxenstore -lpulse-simple -lpulse
CFLAGS=-I./pulseaudio/src
all: backend

backend: backend.o
	$(CC) -g -o backend backend.o \
	-L. $(LDFLAGS) $(LIBS)

backend.o: backend.c
	$(CC) -g -Wall -c $(CFLAGS) backend.c

clean:
	rm backend *.o
