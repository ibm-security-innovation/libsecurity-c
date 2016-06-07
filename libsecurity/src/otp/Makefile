include ../build/common.mk

all: $(LIBDIR)/libotp.a

$(OUTDIR)/otp.o: otp.c $(INCLUDE_PATH)/otp/otp.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(INC) otp.c -o $(OUTDIR)/otp.o

$(OUTDIR)/otpUser.o: otpUser.c $(INCLUDE_PATH)/otp/otpUser.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(INC) otpUser.c -o $(OUTDIR)/otpUser.o

$(LIBDIR)/libotp.a: $(OUTDIR)/otp.o $(OUTDIR)/otpUser.o
	ar rcs $(LIBDIR)/libotp.a $(OUTDIR)/otp.o $(OUTDIR)/otpUser.o

clean:
	rm -f $(OUTDIR)/*.o
	rm -f $(LIBDIR)/libopt.a

.PHONY: clean
