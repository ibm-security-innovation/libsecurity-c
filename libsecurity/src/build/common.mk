AR=ar rcs
LIBSECURITY_DIR=../..
OUTDIR=.
LINUX_OS_VAR=-DLINUX_OS
MBED_OS_VAR=-DMBED_OS
NACL_CRYPTO_VAR=-DNaCl_CRYPTO
OPENSSL_CRYPTO_VAR=-DOPENSSL_CRYPTO
MBEDTLS_CRYPTO_VAR=-DMBEDTLS_CRYPTO
NACL_CPU_TYPE=amd64
GCC_C="GCC_C"
GCC_O="GCC_O"
CLANG="CLANG"
# the default is export COMPILER="GCC_C"

TARGET=$(LINUX_OS_VAR)
#TARGET=$(MBED_OS_VAR)
CRYPTO_TYPE=$(NACL_CRYPTO_VAR)
#CRYPTO_TYPE=$(MBEDTLS_CRYPTO_VAR)
#CRYPTO_TYPE=$(OPENSSL_CRYPTO_VAR)
#DEBUG=-DNDEBUG
#export PURE=1

ifneq ($(TARGET),$(LINUX_OS_VAR))
ifneq ($(TARGET),$(MBED_OS_VAR))
$(error Error! TARGET variable must be set to $(LINUX_OS_VAR) or to $(MBED_OS_VAR))
endif
endif

ifneq ($(CRYPTO_TYPE),$(NACL_CRYPTO_VAR))
ifneq ($(CRYPTO_TYPE),$(MBEDTLS_CRYPTO_VAR))
ifneq ($(CRYPTO_TYPE),$(OPENSSL_CRYPTO_VAR))
$(error Error! CRYPTO_TYPE variable must be set to $(NACL_CRYPTO_VAR) or to $(MBEDTLS_CRYPTO_VAR) or to $(OPENSSL_CRYPTO_VAR))
endif
endif
endif

CFLAGS_COMMON = $(TARGET) $(CRYPTO_TYPE) $(STATIC_F) $(DEBUG) -Wall -Wextra\
    -Wmissing-declarations -Wpointer-arith \
    -Wwrite-strings -Wcast-qual -Wcast-align \
    -Wformat-security  -Wformat-nonliteral \
    -Wmissing-format-attribute \
    -Winline -W -funsigned-char \
    -Wstrict-overflow -fno-strict-aliasing -Wno-missing-field-initializers

ifeq ($(COMPILER),GCC_O)
	CC=gcc
	CFLAGS = -c -std=c99 -O3
	CPPFLAGS = -c -std=c++11 -Os -D _POSIX_C_SOURCE=200809L -fno-exceptions -fno-rtti
else ifeq ($(COMPILER),CLANG)
	CC=clang
	CFLAGS = -fsanitize=address -fno-omit-frame-pointer -c -g -std=c99
	CPPFLAGS = -fsanitize=address -fno-omit-frame-pointer -c -g
	LDFLAGS=-fsanitize=address
else # GCC_C
    export COMPILER="GCC_C"
	CC=gcc
	CFLAGS = -c -std=c99 -g $(COVFLAGS)
	CPPFLAGS = -c -std=c++11 -g -D _POSIX_C_SOURCE=200809L -fno-exceptions -fno-rtti
	CFLAGS-C = -Wmissing-prototypes -Wstrict-prototypes -Wbad-function-cast
endif

ifdef AFL
	CC=/usr/local/bin/afl-gcc
endif

ifdef COV
	COVFLAGS = -fprofile-arcs -ftest-coverage -fPIC -O0 
	LDFLAGS=-lgcov --coverage
endif

ifdef TEST_DIR
	LIBSECURITY_DIR=../../..
else ifdef EXAMPLES_DIR
	LIBSECURITY_DIR=../../..
endif

DEPS_PATH=$(LIBSECURITY_DIR)/../deps
HASH=$(DEPS_PATH)
CRYPTO=$(DEPS_PATH)/crypto/nacl-20110221/build/all

MBEDTLS_INC_DIR=$(DEPS_PATH)/crypto/mbedtls/include
MBEDTLS_LIB_DIR=$(DEPS_PATH)/crypto/mbedtls/library
MBEDTLS_CONFIG_INC=$(MBEDTLS_INC_DIR)/mbedtls/config.h
MBEDTLS_BASE_LIB=-lmbedtls -lmbedx509 -lmbedcrypto

OPENSSL_INC_DIR=$(DEPS_PATH)/crypto/openssl/include/openssl
OPENSSL_LIB_DIR=$(DEPS_PATH)/crypto/openssl
OPENSSL_LIB=-lssl -lcrypto -ldl

INCLUDE_PATH=$(LIBSECURITY_DIR)/include/libsecurity/
LIBDIR=$(LIBSECURITY_DIR)/bin

INC_BASE=-I$(HASH) -I. -I$(LIBSECURITY_DIR)/include
LIB_BASE=-L$(HASH)/hashtab -L$(LIBDIR)

ifeq ($(CRYPTO_TYPE),$(MBEDTLS_CRYPTO_VAR))
	INC=$(INC_BASE) -I$(MBEDTLS_INC_DIR)
	LIB=-L$(MBEDTLS_LIB_DIR) $(LIB_BASE)
	MBEDTLS_LIB=$(MBEDTLS_BASE_LIB)
else ifeq ($(CRYPTO_TYPE),$(OPENSSL_CRYPTO_VAR))
	INC=$(INC_BASE) -I$(OPENSSL_INC_DIR) -I$(MBEDTLS_INC_DIR)
	LIB=-L /usr/local/ssl/lib/ -L$(OPENSSL_LIB_DIR) $(LIB_BASE)
	LIB_SEC=$(OPENSSL_LIB)
else
	RANDOM_BYTES=$(CRYPTO)/lib/$(NACL_CPU_TYPE)/randombytes.o
	CRYPTO_PATH=$(CRYPTO)/include/$(NACL_CPU_TYPE)
	CRYPTO_LIB=$(CRYPTO)/lib/$(NACL_CPU_TYPE)
	LIB_SEC=-lnacl
	INC=$(INC_BASE) -I$(MBEDTLS_INC_DIR) -I$(CRYPTO_PATH)
	LIB=$(LIB_BASE) -L$(MBEDTLS_LIB_DIR) -L$(CRYPTO_LIB)
	MBEDTLS_LIB=$(MBEDTLS_BASE_LIB)
endif

