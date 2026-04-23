CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += -Isrc -Ivendor/jech-dht
LDFLAGS ?= -lsodium -lcrypto -lminiupnpc

SRC := $(wildcard src/*.c) vendor/jech-dht/dht.c
OBJ := $(SRC:.c=.o)

dht44: $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

TESTS := $(patsubst %.c,%,$(wildcard tests/test_*.c))

test: $(TESTS)
	@for t in $(TESTS); do echo "==> $$t"; ./$$t || exit 1; done

tests/test_%: tests/test_%.c $(filter-out src/main.o,$(OBJ))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) dht44 $(TESTS)

.PHONY: clean test
