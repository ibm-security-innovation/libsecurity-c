EXAMPLES_DIR="1"
include ../../build/common.mk

SOURCES=aclUsage.c

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=aclUsage

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lentity -lstorage -lacl -lutils -lm -lmyhash $(LIB_SEC) $(MBEDTLS_LIB)

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS_COMMON) $(CFLAGS) $(CFLAGS-C) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
