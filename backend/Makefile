CC=gcc
LIBS=-lxenctrl -lxenstore -lpulse-simple -lpulse
CFLAGS=-I./pulseaudio/src
all: backend backend-source

backend: backend.o
	$(CC) -g -o backend backend.o \
	-L. $(LDFLAGS) $(LIBS)

backend.o: backend.c
	$(CC) -g -Wall -c $(CFLAGS) backend.c

backend-source: backend-source.o
	$(CC) -g -o backend-source backend-source.o \
	-L. $(LDFLAGS) $(LIBS)

backend-source.o: backend-source.c
	$(CC) -g -Wall -c $(CFLAGS) backend-source.c


clean:
	rm backend *.o
