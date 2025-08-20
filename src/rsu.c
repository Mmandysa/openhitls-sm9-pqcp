#include "net.h"
#include "protocol.h"
#include "scloud_kem.h"
#include <stdio.h>

int main(void) {
    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n"); return -1;
    }

    int lfd = net_listen(DEFAULT_PORT);
    if (lfd < 0) { perror("listen"); return -1; }
    printf("[RSU] listening on %d...\n", DEFAULT_PORT);

    int cfd = net_accept(lfd);
    if (cfd < 0) { perror("accept"); return -1; }
    printf("[RSU] client connected\n");

    SessionKeys ks = {0};
    if (protocol_rsu_handshake(cfd, "京A12345", &ks) == APP_OK) {
        printf("[RSU] handshake OK. k_final_len=%u\n", ks.k_final_len);
    } else {
        printf("[RSU] handshake FAILED\n");
    }

    net_close(cfd);
    net_close(lfd);
    return 0;
}
