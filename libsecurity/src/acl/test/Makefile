TEST_DIR="1"
include ../../build/common.mk

SOURCES=test_acl.c
																	 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test_acl
OTHER= $(LIBDIR)/libacl.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lacl -lentity -lstorage -lmyhash -lutils $(LIB_SEC) $(MBEDTLS_LIB)

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS)  $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
