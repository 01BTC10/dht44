CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += -Iinclude -Isrc -Ivendor/jech-dht
LDFLAGS ?= -lsodium -lcrypto -ljansson

# Library sources only — no CLI / daemon / IPC / UPnP.
LIB_SRC := \
    src/bencode.c \
    src/bep44.c \
    src/state.c \
    src/dht_wrap.c \
    src/lookup.c \
    src/lib.c \
    vendor/jech-dht/dht.c

LIB_OBJ := $(LIB_SRC:.c=.o)

libbep44.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

# Default target: build the library
all: libbep44.a
.PHONY: all

# ---- Tests ----

TESTS := $(patsubst %.c,%,$(wildcard tests/test_*.c))

test: $(TESTS)
	@for t in $(TESTS); do echo "==> $$t"; ./$$t || exit 1; done

tests/test_%: tests/test_%.c $(LIB_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# ---- Integration ----

INTEGRATION_TESTS := $(wildcard tests/integration/*.sh)

tests/lib_driver: tests/lib_driver.c libbep44.a
	$(CC) $(CFLAGS) $< libbep44.a -o $@ $(LDFLAGS)

integration: tests/lib_driver
	@for s in $(INTEGRATION_TESTS); do echo "==> $$s"; bash $$s || exit 1; done

# ---- Examples ----

examples/minimal: examples/minimal.c libbep44.a
	$(CC) $(CFLAGS) $< libbep44.a -o $@ $(LDFLAGS)

example: examples/minimal
.PHONY: example

clean:
	rm -f $(LIB_OBJ) libbep44.a $(TESTS) tests/lib_driver examples/minimal

.PHONY: clean test integration
