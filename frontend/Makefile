CC=gcc
LIBS=-lxenctrl -lxenstore
CFLAGS=-fPIC -I./pulseaudio/src
all: module-xenpv-sink.so

module-xenpv-sink.so: module-xenpv-sink.o
	$(CC) -shared -o module-xenpv-sink.so module-xenpv-sink.o \
	-L. $(LDFLAGS) $(LIBS)

module-xenpv-sink.o: module-xenpv-sink.c
	$(CC) -Wall -c $(CFLAGS) module-xenpv-sink.c

clean:
	rm *.so *.o
