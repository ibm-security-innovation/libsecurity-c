include ../build/common.mk

all: $(LIBDIR)/libstorage.a

$(OUTDIR)/secureStorage.o: secureStorage.c $(INCLUDE_PATH)/storage/secureStorage.h
	$(CC) $(MBED_LINUX) $(CFLAGS_COMMON) $(CFLAGS) $(INC) secureStorage.c -o $(OUTDIR)/secureStorage.o

$(LIBDIR)/libstorage.a: $(OUTDIR)/secureStorage.o
	$(AR) $(LIBDIR)/libstorage.a $(OUTDIR)/secureStorage.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libstorage.a

.PHONY: clean
