CC=gcc
CFLAGS=-c
LDFLAGS=
SOURCES=unique.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=unique
INC=-I/usr/include/mylib
LIB=-L/usr/lib/mylib

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIB) -lmyhash

.c.o:
	$(CC) $(CFLAGS) $(INC) $< -o $@


