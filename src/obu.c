#include "net.h"
#include "protocol.h"
#include "scloud_kem.h"
#include <stdio.h>

int main(void) {
    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n"); return -1;
    }

    int fd = net_connect("127.0.0.1", DEFAULT_PORT);
    if (fd < 0) { perror("connect"); return -1; }
    printf("[OBU] connected\n");

    SessionKeys ks = {0};
    if (protocol_obu_handshake(fd, "京A12345", &ks) == APP_OK) {
        printf("[OBU] handshake OK. k_final_len=%u\n", ks.k_final_len);
    } else {
        printf("[OBU] handshake FAILED\n");
    }

    net_close(fd);
    return 0;
}
