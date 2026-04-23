CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += -Isrc -Ivendor/jech-dht
LDFLAGS ?= -lsodium -lcrypto -lminiupnpc -ljansson

SRC := $(wildcard src/*.c) vendor/jech-dht/dht.c
OBJ := $(SRC:.c=.o)

dht44: $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

TESTS := $(patsubst %.c,%,$(wildcard tests/test_*.c))

test: $(TESTS)
	@for t in $(TESTS); do echo "==> $$t"; ./$$t || exit 1; done

tests/test_%: tests/test_%.c $(filter-out src/main.o,$(OBJ))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

INTEGRATION_TESTS := $(wildcard tests/integration/*.sh)

integration: dht44
	@for s in $(INTEGRATION_TESTS); do echo "==> $$s"; bash $$s || exit 1; done

clean:
	rm -f $(OBJ) dht44 $(TESTS)

.PHONY: clean test integration
