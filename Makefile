PREFIX ?= /usr/local
PAM_DIR ?= $(PREFIX)/lib/security
CONFIG_DIR ?= /etc/security
BUILD_DIR ?= build
CC ?= cc

CFLAGS ?= -O2 -fPIC -Wall -Wextra -Wpedantic
LDFLAGS ?=
LDLIBS ?= -lpam -lcurl -ljson-c

.PHONY: build install clean

build:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared \
		-Wl,-z,relro,-z,now \
		-o $(BUILD_DIR)/pam_ssh_oidc.so src/pam_ssh_oidc.c \
		$(LDFLAGS) $(LDLIBS)

install: build
	install -d -m 0755 $(DESTDIR)$(PAM_DIR)
	install -m 0755 $(BUILD_DIR)/pam_ssh_oidc.so $(DESTDIR)$(PAM_DIR)/pam_ssh_oidc.so
	@if [ ! -e "$(DESTDIR)$(CONFIG_DIR)/pam-ssh-oidc.conf" ]; then \
		install -d -m 0755 "$(DESTDIR)$(CONFIG_DIR)"; \
		install -m 0600 config/pam-ssh-oidc.conf.example "$(DESTDIR)$(CONFIG_DIR)/pam-ssh-oidc.conf"; \
	fi

clean:
	rm -rf $(BUILD_DIR)
