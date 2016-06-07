include ../build/common.mk

all: $(LIBDIR)/libpassword.a

$(OUTDIR)/password.o: password.c $(INCLUDE_PATH)/password/password.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(INC) password.c -o $(OUTDIR)/password.o

$(LIBDIR)/libpassword.a: $(OUTDIR)/password.o
	$(AR) $(LIBDIR)/libpassword.a $(OUTDIR)/password.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libpassword.a

.PHONY: clean
