# tpm-pcr-dump — TPM 2.0 PCR reader, event log parser, and attestation tool
#
# Copyright (c) 2026 isecwire GmbH
# SPDX-License-Identifier: MIT

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L
CFLAGS   += -Iinclude -Isrc
LDFLAGS  :=
LIBS     := -lssl -lcrypto

PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin

# Source files
SRCDIR   := src
SRCS     := $(SRCDIR)/main.c            \
            $(SRCDIR)/tpm_interface.c    \
            $(SRCDIR)/pcr_verify.c       \
            $(SRCDIR)/json_writer.c      \
            $(SRCDIR)/utils.c            \
            $(SRCDIR)/color.c            \
            $(SRCDIR)/table_fmt.c        \
            $(SRCDIR)/event_types.c      \
            $(SRCDIR)/event_log.c        \
            $(SRCDIR)/simulator.c        \
            $(SRCDIR)/attestation.c      \
            $(SRCDIR)/commands.c

OBJDIR   := build
OBJS     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

TARGET   := tpm-pcr-dump

# Test source files
TESTDIR  := tests
TSRCS    := $(TESTDIR)/test_main.c       \
            $(TESTDIR)/test_utils.c      \
            $(TESTDIR)/test_json_writer.c \
            $(TESTDIR)/test_pcr_verify.c

# Library sources (everything except main.c -- those are linked into tests)
LIB_SRCS := $(SRCDIR)/utils.c            \
            $(SRCDIR)/json_writer.c       \
            $(SRCDIR)/pcr_verify.c        \
            $(SRCDIR)/tpm_interface.c     \
            $(SRCDIR)/color.c             \
            $(SRCDIR)/table_fmt.c         \
            $(SRCDIR)/event_types.c       \
            $(SRCDIR)/event_log.c         \
            $(SRCDIR)/simulator.c         \
            $(SRCDIR)/attestation.c       \
            $(SRCDIR)/commands.c

LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(LIB_SRCS))
TEST_OBJS:= $(patsubst $(TESTDIR)/%.c,$(OBJDIR)/%.o,$(TSRCS))

TEST_BIN := run_tests

# -- Targets --

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: $(TESTDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(TESTDIR) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET) $(TEST_BIN)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
