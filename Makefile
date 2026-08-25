# Simple Socks5 - build rules
#
# Tested on Ubuntu 24.04 LTS (gcc 13, OpenSSL 3.0). Requires g++ and the
# OpenSSL development headers:
#
#     sudo apt install build-essential libssl-dev
#
#     make linux      - build bin/socks5 and bin/blowcrypt
#     make clean
#
# Note: OpenSSL is located with pkg-config. Override SSL_CFLAGS / SSL_LIBS on
# the command line to build against an OpenSSL installed somewhere else.

PKG_CONFIG ?= pkg-config
SSL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags openssl)
SSL_LIBS   ?= $(shell $(PKG_CONFIG) --libs openssl)

CXX      ?= g++
CXXFLAGS ?= -O2 -g -std=c++17 -W -Wall -fno-strict-aliasing
CPPFLAGS  = -Iinclude $(SSL_CFLAGS)
LDFLAGS  ?=
LDLIBS    = $(SSL_LIBS) -lpthread

# Hardening flags, on by default. Build with `make linux HARDEN=` to drop them.
HARDEN ?= 1
ifeq ($(HARDEN),1)
CXXFLAGS += -fstack-protector-strong -fPIE
LDFLAGS  += -pie -Wl,-z,relro,-z,now
endif

COMMON_OBJS = src/config.o src/lock.o src/counter.o src/tools.o \
              src/userlist.o src/sslcompat.o
SOCKS5_OBJS = src/socks5.o $(COMMON_OBJS)
BLOW_OBJS   = src/blowcrypt.o $(COMMON_OBJS)

HEADERS = include/global.h include/tools.h include/config.h include/lock.h \
          include/counter.h include/userlist.h include/sslcompat.h

%.o: %.cc $(HEADERS)
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

all:
	@echo "To compile socks5 type"
	@echo "  - 'make linux' to compile under linux"
	@echo "  - or 'make clean'"

linux: bin/socks5 bin/blowcrypt

bin/socks5: $(SOCKS5_OBJS)
	$(CXX) $(LDFLAGS) $(SOCKS5_OBJS) -o $@ $(LDLIBS)

bin/blowcrypt: $(BLOW_OBJS)
	$(CXX) $(LDFLAGS) $(BLOW_OBJS) -o $@ $(LDLIBS)

# Static linking is deliberately NOT offered any more. OpenSSL 3 loads its
# providers (including the "legacy" provider that Blowfish lives in) as shared
# modules via dlopen(), so a statically linked binary cannot read an encrypted
# config file. Use the dynamic build.

clean:
	@rm -f bin/socks5 bin/blowcrypt bin/socks5-static bin/blowcrypt-static src/*.o
	@echo "Clean succesful"

.PHONY: all linux clean
