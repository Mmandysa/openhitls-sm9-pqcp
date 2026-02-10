#include "net.h"
#include "pqtls.h"
#include "scloud_kem.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief Server（服务端）演示入口：执行 PQTLS 握手，并在加密通道内收发一条 APP_TEXT
 */
int main(void)
{
    const char *server_id = "RSU_001";
    const char *expected_client_id = "琼B12345";

    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n");
        return -1;
    }

    int lfd = net_listen(DEFAULT_PORT);
    if (lfd < 0) {
        perror("listen");
        return -1;
    }
    printf("[SERVER] listening on %d...\n", DEFAULT_PORT);

    int cfd = net_accept(lfd);
    if (cfd < 0) {
        perror("accept");
        net_close(lfd);
        return -1;
    }
    printf("[SERVER] client connected\n");

    PQTLS_Session sess;
    if (pqtls_server_handshake(cfd, expected_client_id, server_id, &sess) != APP_OK) {
        fprintf(stderr, "[SERVER] handshake FAILED\n");
        net_close(cfd);
        net_close(lfd);
        return -1;
    }
    printf("[SERVER] handshake OK\n");

    uint16_t app_type = 0;
    uint8_t buf[1024];
    uint32_t buf_len = 0;
    if (pqtls_recv_appdata(cfd, &sess, &app_type, buf, sizeof(buf), &buf_len) != APP_OK) {
        fprintf(stderr, "[SERVER] recv appdata failed\n");
        net_close(cfd);
        net_close(lfd);
        return -1;
    }
    printf("[SERVER] recv app_type=0x%04x, len=%u\n", app_type, buf_len);
    if (app_type == PQTLS_APP_TEXT) {
        printf("[SERVER] text: %.*s\n", (int)buf_len, (const char *)buf);
    }

    const char *resp = "Hello client, this is server. Secure channel established.";
    if (pqtls_send_appdata(cfd, &sess, PQTLS_APP_TEXT, (const uint8_t *)resp, (uint32_t)strlen(resp)) != APP_OK) {
        fprintf(stderr, "[SERVER] send appdata failed\n");
        net_close(cfd);
        net_close(lfd);
        return -1;
    }
    printf("[SERVER] sent APP_TEXT\n");

    net_close(cfd);
    net_close(lfd);
    scloud_global_cleanup();
    return 0;
}
