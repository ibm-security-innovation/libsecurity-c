EXAMPLES_DIR="1"
include ../../build/common.mk

SOURCES=iotClient.c
INTERNAL_LOG=-DINTERNAL_LOG

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=iotClient
OTHER=$(LIBDIR)/libutils.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)

clean:
	rm -f *.o


$(EXECUTABLE): $(OBJECTS)
	$(CC) $(TARGET) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lm -lutils -lmyhash $(LIB_SEC) $(MBEDTLS_LIB)

.c.o:
	$(CC) $(INTERNAL_LOG) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@
