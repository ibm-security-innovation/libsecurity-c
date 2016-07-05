include versions.mk

CRYPTO=crypto
NACL_LIB=nacl-$(NACL_VER)
NACL_FILE=$(NACL_LIB).tar.bz2

MBEDTLS_FILE=mbedtls-$(MBEDTLS_VER)-apache.tgz
MBEDTLS_LIB=mbedtls-$(MBEDTLS_VER)

OPENSSL_LIB=openssl-$(OPENSSL_VER)
OPENSSL_FILE=$(OPENSSL_LIB).tar.gz

all: download_deps build_deps

#download_deps: download_nacl download_mbedtls
download_deps: download_openssl

.PHONY: download_deps

build_deps: build_openssl build_hashtab
#build_deps: build_nacl build_mbedtls build_hashtab

.PHONY: build_deps

download_nacl:
	@echo "Downloading $(NACL_LIB) ..."
	mkdir -p $(CRYPTO)
	curl -o $(CRYPTO)/$(NACL_FILE) http://hyperelliptic.org/nacl/$(NACL_FILE)

.PHONY: download_nacl

build_nacl:
	@echo "Building NaCl-$(NACL_VER) it may take a few minutes..."
	bunzip2 < $(CRYPTO)/$(NACL_FILE) | tar -xf - 
	rm -rf $(CRYPTO)/$(NACL_LIB)
	mv $(NACL_LIB) $(CRYPTO)
	rm -f $(CRYPTO)/$(NACL_FILE)
	(cd ./$(CRYPTO)/$(NACL_LIB) && ./do && cd build && ln -s * all)
	@echo "Done"

download_mbedtls:
	@echo "Downloading $(MBEDTLS_LIB) ..."
	@curl --fail -O https://tls.mbed.org/download/$(MBEDTLS_FILE) || \
		(echo "Error downloading mbedtls: Check the MBEDTLS_VER in deps/versions.mk and current version in https://tls.mbed.org/download" ; exit 1)
	tar xzf $(MBEDTLS_FILE) -C $(CRYPTO)
	rm -f $(MBEDTLS_FILE)

.PHONY: download_mbedtls

build_mbedtls:
	$(MAKE) -C $(CRYPTO)/$(MBEDTLS_LIB) lib
	rm -f $(CRYPTO)/mbedtls
	ln -s $(MBEDTLS_LIB) $(CRYPTO)/mbedtls

download_openssl:
	@echo "Downloading $(OPENSSL_LIB) ..."
#	curl -o $(CRYPTO)/$(OPENSSL_FILE) https://www.openssl.org/source/$(OPENSSL_FILE)
#	tar xzf $(CRYPTO)/$(OPENSSL_FILE) -C $(CRYPTO)
#	rm -f $(CRYPTO)/$(OPENSSL_FILE)

.PHONY: download_mbedtls

build_openssl:
#	(cd $(CRYPTO)/$(OPENSSL_LIB) &&	./Configure --openssldir=openssl linux-x86_64 && ./config no-idea no-camellia no-bf no-cast no-des no-rc2 no-rc4 no-rc5 no-md2 no-md4 \
# no-ripemd no-mdc2 no-dsa no-dh)
	(cd $(CRYPTO)/$(OPENSSL_LIB) &&	mkdir -p library && ./Configure --openssldir=openssl linux-x86_64 && ./config no-rc2 && make depend)
	(cd $(CRYPTO)/$(OPENSSL_LIB) && make && sudo make install_sw)
	rm -f $(CRYPTO)/openssl
	ln -s $(OPENSSL_LIB) $(CRYPTO)/openssl

build_hashtab:
	$(MAKE) -C hashtab	

clean:
	rm -rf $(CRYPTO)/$(NACL_LIB)
	rm -rf $(CRYPTO)/$(MBEDTLS_LIB)

.PHONY: clean
