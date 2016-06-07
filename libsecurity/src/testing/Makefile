include ../build/common.mk

SOURCES=parserCommon.c fastUser.c fastOtp.c fastOtpUser.c fastAccounts.c fastAcl.c fastStorage.c fastPassword.c
 																	 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=libsecurity
OTHER=

all: $(SOURCES) $(EXECUTABLE) $(OTHER)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(RANDOM_BYTES) -o $@ $(LIB) -laccounts -lacl -lpassword -lentity -lsalt -lstorage -lotp -lm -lmyhash -lutils $(LIB_SEC) $(MBEDTLS_LIB)

.c.o:
	$(CC) $(TARGET) $(CRYPTO_TYPE) $(CFLAGS) $(STATIC_F) $(INC) $< -o $@

clean:
	rm -rf *.o
	
.PHONY: clean
