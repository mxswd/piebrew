# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The Piebrew authors
#
#   make [OUT=DIR]        piebrew, in DIR (default .; links libcurl,
#                         libcrypto, libarchive)
#   make install DESTDIR=DIR

VERSION := 0.1.2
CC      ?= cc
CFLAGS  ?= -O2 -g
HOSTCC  ?= cc
OUT     ?= .
SRCS    := piebrew.c util.c fetch.c formula.c bottle.c relocate.c codesign.c links.c deb.c cjson/cJSON.c
HEADERS := piebrew.h cjson/cJSON.h

all: $(OUT)/piebrew

piebrew: $(OUT)/piebrew

$(OUT)/piebrew: $(SRCS) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -Wall -DPIEBREW_VERSION='"$(VERSION)"' -o $@ $(SRCS) $(LDFLAGS) \
		-lcurl -lcrypto -larchive

install: $(OUT)/piebrew
	install -d $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/man/man1
	install -m 755 $(OUT)/piebrew $(DESTDIR)/usr/bin/piebrew
	install -m 644 piebrew.1 $(DESTDIR)/usr/share/man/man1/piebrew.1

clean:
	rm -rf piebrew piebrew.dSYM

.PHONY: all install clean
