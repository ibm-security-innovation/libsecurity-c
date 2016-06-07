LIBSECURITY_DIR ?= ./libsecurity/src

all: libsecurity-c

deps:
	$(MAKE) -C deps download_deps build_deps

libsecurity-c:
	mkdir -p ./libsecurity/bin
	$(MAKE) -C $(LIBSECURITY_DIR)/accounts
	$(MAKE) -C $(LIBSECURITY_DIR)/acl
	$(MAKE) -C $(LIBSECURITY_DIR)/entity
	$(MAKE) -C $(LIBSECURITY_DIR)/password
	$(MAKE) -C $(LIBSECURITY_DIR)/otp
	$(MAKE) -C $(LIBSECURITY_DIR)/salt
	$(MAKE) -C $(LIBSECURITY_DIR)/utils
	$(MAKE) -C $(LIBSECURITY_DIR)/storage
	$(MAKE) -C $(LIBSECURITY_DIR)/examples/fullExample
	$(MAKE) -C $(LIBSECURITY_DIR)/examples/secureStorageExample

depsclean:
	$(MAKE) -C deps clean

clean:
	$(MAKE) -C $(LIBSECURITY_DIR)/accounts clean
	$(MAKE) -C $(LIBSECURITY_DIR)/acl clean
	$(MAKE) -C $(LIBSECURITY_DIR)/entity clean
	$(MAKE) -C $(LIBSECURITY_DIR)/password clean
	$(MAKE) -C $(LIBSECURITY_DIR)/otp clean
	$(MAKE) -C $(LIBSECURITY_DIR)/salt clean
	$(MAKE) -C $(LIBSECURITY_DIR)/utils clean
	$(MAKE) -C $(LIBSECURITY_DIR)/storage clean
	$(MAKE) -C $(LIBSECURITY_DIR)/examples/fullExample clean
	$(MAKE) -C $(LIBSECURITY_DIR)/examples/secureStorageExample clean

.PHONY: all clean depclean deps libsecurity-c
