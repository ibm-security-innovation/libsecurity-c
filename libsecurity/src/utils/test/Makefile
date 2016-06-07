TEST_DIR="1"
include ../../build/common.mk

SOURCES=test_utils.c
INTERNAL_LOG=-DINTERNAL_LOG

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test_utils
OTHER=$(LIBDIR)/libutils.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(TARGET) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -laccounts -lpassword -lentity -lacl -lsalt -lstorage -lm -lutils -lmyhash $(LIB_SEC) $(MBEDTLS_LIB)

.c.o:
	$(CC) $(INTERNAL_LOG) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
