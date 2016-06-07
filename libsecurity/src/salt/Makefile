include ../build/common.mk

all: $(LIBDIR)/libsalt.a

$(OUTDIR)/salt.o: salt.c $(INCLUDE_PATH)/salt/salt.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(INC) salt.c -o $(OUTDIR)/salt.o

$(LIBDIR)/libsalt.a: $(OUTDIR)/salt.o
	$(AR) $(LIBDIR)/libsalt.a $(OUTDIR)/salt.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(OUTDIR)/libsalt.a

.PHONY: clean
