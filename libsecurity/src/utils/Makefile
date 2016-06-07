include ../build/common.mk

EXTRA_CFLAGS =

ifeq ($(COMPILER),GCC_O)
	EXTRA_CFLAGS = -D _POSIX_C_SOURCE=200809L -pedantic
else ifeq ($(COMPILER),GCC_C)
	EXTRA_CFLAGS = -D _POSIX_C_SOURCE=200809L -pedantic
endif

all: $(LIBDIR)/libutils.a

$(OUTDIR)/itemsList.o: itemsList.c $(INCLUDE_PATH)/utils/itemsList.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS-C) $(INC) itemsList.c -o $(OUTDIR)/itemsList.o

$(OUTDIR)/utils.o: utils.c $(INCLUDE_PATH)/utils/utils.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS-C) $(INC) utils.c -o $(OUTDIR)/utils.o

$(OUTDIR)/sysLog.o: sysLog.c $(INCLUDE_PATH)/utils/sysLog_int.h $(INCLUDE_PATH)/utils/sysLog.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS-C) $(INC) sysLog.c -o $(OUTDIR)/sysLog.o

$(OUTDIR)/crypto.o: crypto.c $(INCLUDE_PATH)/utils/crypto_int.h $(INCLUDE_PATH)/utils/crypto.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_COMMON) $(CFLAGS-C) $(INC) crypto.c -o $(OUTDIR)/crypto.o

$(OUTDIR)/hwAdapters.o: hwAdapters.cpp $(INCLUDE_PATH)/utils/hwAdapters.h
	$(CC) $(CFLAGS_COMMON) $(CPPFLAGS) $(EXTRA_CFLAGS) $(INC) hwAdapters.cpp -o $(OUTDIR)/hwAdapters.o

$(OUTDIR)/fileAdapters.o: fileAdapters.cpp $(INCLUDE_PATH)/utils/fileAdapters.h
	$(CC) $(CFLAGS_COMMON) $(CPPFLAGS) $(EXTRA_CFLAGS) $(INC) fileAdapters.cpp -o $(OUTDIR)/fileAdapters.o

$(OUTDIR)/networkAdapters.o: networkAdapters.cpp $(INCLUDE_PATH)/utils/networkAdapters_int.h $(INCLUDE_PATH)/utils/networkAdapters.h
	$(CC) $(CFLAGS_COMMON) $(CPPFLAGS) $(EXTRA_CFLAGS) $(INC) networkAdapters.cpp -o $(OUTDIR)/networkAdapters.o

$(OUTDIR)/dtlsClient.o: dtlsClient.cpp $(INCLUDE_PATH)/utils/dtlsClient.h
	$(CC) $(CFLAGS_COMMON) $(CPPFLAGS) $(EXTRA_CFLAGS) $(INC) dtlsClient.cpp -o $(OUTDIR)/dtlsClient.o

$(LIBDIR)/libutils.a: $(OUTDIR)/utils.o $(OUTDIR)/itemsList.o $(OUTDIR)/sysLog.o $(OUTDIR)/crypto.o $(OUTDIR)/hwAdapters.o $(OUTDIR)/fileAdapters.o $(OUTDIR)/networkAdapters.o $(OUTDIR)/dtlsClient.o
	$(AR) $(LIBDIR)/libutils.a $(OUTDIR)/itemsList.o $(OUTDIR)/sysLog.o $(OUTDIR)/crypto.o $(OUTDIR)/hwAdapters.o $(OUTDIR)/fileAdapters.o $(OUTDIR)/networkAdapters.o $(OUTDIR)/dtlsClient.o $(OUTDIR)/utils.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libutils.a

.PHONY: clean
	