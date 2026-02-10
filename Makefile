CC ?= gcc

CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra
INCLUDES := -I/usr/local/include -I/usr/local/include/hitls -I/usr/local/include/hitls/bsl -I/usr/local/include/hitls/crypto
LDFLAGS := -L/usr/local/lib -Wl,-rpath,/usr/local/lib

PQTLS_COMMON_SRCS := \
	src/net.c \
	src/pqtls.c \
	src/pqtls_handshake.c \
	src/pqtls_record.c \
	src/pqtls_codec.c \
	src/pqtls_crypto.c \
	src/pqtls_keyschedule.c \
	src/pqtls_sm9_auth.c \
	src/scloud_kem.c \
	src/sm9_utils.c

PQTLS_LDLIBS := -lgmssl -lhitls_crypto -lhitls_bsl -lpqcp_provider -ldl -lpthread

.PHONY: all clean setup_keys client server obu rsu test run_test

all: setup_keys server client test

setup_keys: bin/setup_keys
server: bin/server
client: bin/client
rsu: server
obu: client
test: bin/pqtls_test
run_test: test
	./bin/pqtls_test

bin:
	mkdir -p bin

bin/setup_keys: src/setup_keys.c src/sm9_utils.c | bin
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) -lgmssl

bin/server: src/server.c $(PQTLS_COMMON_SRCS) | bin
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(PQTLS_LDLIBS)

bin/client: src/client.c $(PQTLS_COMMON_SRCS) | bin
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(PQTLS_LDLIBS)

bin/pqtls_test: src/pqtls_test.c $(PQTLS_COMMON_SRCS) | bin
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(PQTLS_LDLIBS)

clean:
	rm -rf bin
