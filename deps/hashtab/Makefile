CFLAGS = -c -O
AR=ar rcs
CC=gcc
OUTDIR=.

#.c.o:
#	$(CC) $(CFLAGS) -c $<

all: recycle lookupa hashtab libmyhash

recycle: recycle.c standard.h recycle.h
	$(CC) $(CFLAGS) recycle.c -o $(OUTDIR)/recycle.o

lookupa: lookupa.c standard.h lookupa.h
	$(CC) $(CFLAGS) lookupa.c -o $(OUTDIR)/lookupa.o

hashtab: hashtab.c standard.h recycle.h lookupa.h hashtab.h
	$(CC) $(CFLAGS) hashtab.c -o $(OUTDIR)/hashtab.o

libmyhash: $(OUTDIR)/recycle.o $(OUTDIR)/lookupa.o $(OUTDIR)/hashtab.o
	$(AR) $(OUTDIR)/libmyhash.a $(OUTDIR)/recycle.o $(OUTDIR)/lookupa.o $(OUTDIR)/hashtab.o

#recycle.o : recycle.c standard.h recycle.h
#lookupa.o : lookupa.c standard.h lookupa.h
#hashtab.o : hashtab.c standard.h recycle.h lookupa.h hashtab.h

clean:
	rm -f $(OUTDIR)/*.[oa]
