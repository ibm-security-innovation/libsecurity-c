include ../build/common.mk

all: $(LIBDIR)/libaccounts.a

$(OUTDIR)/accounts.o: accounts.c $(INCLUDE_PATH)/accounts/accounts.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(INC) accounts.c -o $(OUTDIR)/accounts.o

$(LIBDIR)/libaccounts.a: $(OUTDIR)/accounts.o
	$(AR) $(LIBDIR)/libaccounts.a $(OUTDIR)/accounts.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libaccounts.a

.PHONY: clean
