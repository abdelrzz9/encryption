CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS =
AR      = ar rcs

SRCS    = src/aes.c src/rsa.c src/chacha20.c src/sha.c src/hmac.c src/utils.c
OBJS    = $(SRCS:.c=.o)
PICOBJS = $(SRCS:.c=.pic.o)

CLI_SRC = cli/main.c
CLI_OBJ = cli/main.o

LIBA    = libencripto.a
LIBSO   = libencripto.so
CLI_BIN = encripto

TEST_SRCS = $(wildcard tests/test_*.c)
TEST_BINS = $(TEST_SRCS:.c=)

INSTALL_DIR = /usr/local
INSTALL_INC = $(INSTALL_DIR)/include
INSTALL_LIB = $(INSTALL_DIR)/lib
INSTALL_BIN = $(INSTALL_DIR)/bin

.PHONY: all lib cli tests install uninstall clean coverage

all: lib cli

# ── Static library ──────────────────────────────────────────

$(LIBA): $(OBJS)
	$(AR) $@ $^

# ── Shared library (compiled with -fPIC) ────────────────────

%.pic.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(LIBSO): $(PICOBJS)
	$(CC) -shared -fPIC -o $@ $^

lib: $(LIBA) $(LIBSO)

# ── CLI binary ──────────────────────────────────────────────

$(CLI_BIN): $(LIBA) $(CLI_OBJ)
	$(CC) $(CFLAGS) -o $@ $(CLI_OBJ) $(LIBA) $(LDFLAGS)

cli: $(CLI_BIN)

# ── Tests ───────────────────────────────────────────────────

tests/%: tests/%.c $(LIBA)
	$(CC) $(CFLAGS) -o $@ $< $(LIBA) $(LDFLAGS)

tests: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t; \
	done

# ── Install ─────────────────────────────────────────────────

install: lib $(CLI_BIN)
	install -d $(INSTALL_INC) $(INSTALL_LIB) $(INSTALL_BIN)
	install -m 644 include/encripto.h $(INSTALL_INC)/
	install -m 644 $(LIBA) $(INSTALL_LIB)/
	install -m 755 $(LIBSO) $(INSTALL_LIB)/
	install -m 755 $(CLI_BIN) $(INSTALL_BIN)/

uninstall:
	rm -f $(INSTALL_INC)/encripto.h
	rm -f $(INSTALL_LIB)/$(LIBA)
	rm -f $(INSTALL_LIB)/$(LIBSO)
	rm -f $(INSTALL_BIN)/$(CLI_BIN)

# ── Clean ───────────────────────────────────────────────────

clean:
	rm -f $(OBJS) $(PICOBJS) $(CLI_OBJ)
	rm -f $(LIBA) $(LIBSO) $(CLI_BIN) $(TEST_BINS)
	rm -f tests/*.o
	rm -f *.gcda *.gcno *.gcov
	rm -f src/*.gcda src/*.gcno
	rm -f cli/*.gcda cli/*.gcno

# ── Coverage ────────────────────────────────────────────────

coverage: CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O0 -g -Iinclude \
                   --coverage -fprofile-arcs -ftest-coverage
coverage: LDFLAGS = --coverage
coverage: clean lib tests
	@gcov -r $(SRCS) 2>/dev/null; true
