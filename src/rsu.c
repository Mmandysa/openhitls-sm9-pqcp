#include "net.h"
#include "protocol.h"
#include "scloud_kem.h"
#include <stdio.h>

int main(void) {
    const char *rsu_exch_id = "RSU_001";
    const char *expected_obu_sign_id = "琼B12345";
    const char *expected_obu_exch_id = "琼B12345";
    
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
    if (protocol_rsu_handshake(cfd, expected_obu_sign_id, expected_obu_exch_id, rsu_exch_id, &ks) == APP_OK) {
        printf("[RSU] handshake OK. k_final_len=%u\n", ks.k_final_len);
    } else {
        printf("[RSU] handshake FAILED\n");
    }

    net_close(cfd);
    net_close(lfd);
    return 0;
}
