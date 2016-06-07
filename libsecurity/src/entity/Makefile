include ../build/common.mk

all: $(LIBDIR)/libentity.a

$(OUTDIR)/entity.o: entity.c $(INCLUDE_PATH)/entity/entity_int.h $(INCLUDE_PATH)/entity/entity.h
	$(CC) $(MBED_LINUX) $(CFLAGS) $(CFLAGS_COMMON) $(CFLAGS-C) $(INC) entity.c -o $(OUTDIR)/entity.o

$(OUTDIR)/entityManager.o: entityManager.c $(INCLUDE_PATH)/entity/entityManager.h
	$(CC) $(MBED_LINUX) $(CFLAGS) $(CFLAGS_COMMON) $(CFLAGS-C) $(INC) entityManager.c -o $(OUTDIR)/entityManager.o

$(LIBDIR)/libentity.a: $(OUTDIR)/entity.o $(OUTDIR)/entityManager.o
	$(AR) $(LIBDIR)/libentity.a $(OUTDIR)/entity.o $(OUTDIR)/entityManager.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libentity.a

.PHONY: clean
