CC=gcc
LIBS=-L/usr/lib/xen-4.1/lib -lxenctrl -lxenstore
CFLAGS= -fPIC -I./pulseaudio/src
all: module-xenpv-sink.so module-xenpv-source.so

module-xenpv-sink.so: module-xenpv-sink.o
	$(CC) -shared -o module-xenpv-sink.so module-xenpv-sink.o \
	-L. $(LDFLAGS) $(LIBS)

module-xenpv-sink.o: module-xenpv-sink.c
	$(CC) -Wall -c $(CFLAGS) module-xenpv-sink.c

module-xenpv-source.so: module-xenpv-source.o
	$(CC) -shared -o module-xenpv-source.so module-xenpv-source.o \
	-L. $(LDFLAGS) $(LIBS)

module-xenpv-source.o: module-xenpv-source.c
	$(CC) -Wall -c $(CFLAGS) module-xenpv-source.c


clean:
	rm *.so *.o
