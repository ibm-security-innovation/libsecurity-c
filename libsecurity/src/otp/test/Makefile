TEST_DIR="1"
include ../../build/common.mk

SOURCES=test_otp.c test_otpUser.c
																 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test_otp
OTHER=$(LIBDIR)/libotp.a

all: $(SOURCES) $(EXECUTABLE) $(OTHER)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -lstorage -lotp -lentity -lacl -lutils $(LIB_SEC) $(MBEDTLS_LIB) -lm -lmyhash

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -f *.o

.PHONY: clean
