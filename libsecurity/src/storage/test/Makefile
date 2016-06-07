TEST_DIR="1"
include ../../build/common.mk

SOURCES=test_secureStorage.c

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test_secureStorage
OTHER=$(LIBDIR)/libstorage.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lstorage -lutils $(LIB_SEC) $(MBEDTLS_LIB) -lmyhash -lentity

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
