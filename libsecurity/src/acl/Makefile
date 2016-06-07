include ../build/common.mk

all: $(LIBDIR)/libacl.a

$(OUTDIR)/aclEntry.o: aclEntry.c $(INCLUDE_PATH)/acl/aclEntry_int.h $(INCLUDE_PATH)/acl/aclEntry.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(CFLAGS-C) $(INC) aclEntry.c -o $(OUTDIR)/aclEntry.o

$(OUTDIR)/acl.o: acl.c $(INCLUDE_PATH)/acl/acl.h aclEntry.c $(INCLUDE_PATH)/acl/aclEntry.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(CFLAGS-C) $(INC) acl.c -o $(OUTDIR)/acl.o

$(LIBDIR)/libacl.a: $(OUTDIR)/acl.o $(OUTDIR)/aclEntry.o
	$(AR) $(LIBDIR)/libacl.a $(OUTDIR)/acl.o $(OUTDIR)/aclEntry.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libacl.a

.PHONY: clean
