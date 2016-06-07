TEST_DIR="1"
include ../../build/common.mk

SOURCES=test_password.c
																	 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test_password
OTHER=$(LIBDIR)/libpassword.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lpassword -lentity -lacl -lsalt -lstorage -lutils $(LIB_SEC) $(MBEDTLS_LIB) -lm -lmyhash

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
