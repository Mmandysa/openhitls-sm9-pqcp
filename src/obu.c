#include "net.h"
#include "pqtls.h"
#include "scloud_kem.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief OBU（客户端）演示入口：执行 PQTLS 握手，并在加密通道内收发一条 APP_TEXT
 */
int main(void)
{
    const char *obu_id = "琼B12345";
    const char *expected_rsu_id = "RSU_001";

    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n");
        return -1;
    }

    int fd = net_connect("127.0.0.1", DEFAULT_PORT);
    if (fd < 0) {
        perror("connect");
        return -1;
    }
    printf("[OBU] connected\n");

    PQTLS_Session sess;
    if (pqtls_client_handshake(fd, obu_id, expected_rsu_id, &sess) != APP_OK) {
        fprintf(stderr, "[OBU] handshake FAILED\n");
        net_close(fd);
        return -1;
    }
    printf("[OBU] handshake OK\n");

    const char *msg = "Hello RSU, this is OBU (PQTLS + SM9 + SCloud+).";
    if (pqtls_send_appdata(fd, &sess, PQTLS_APP_TEXT, (const uint8_t *)msg, (uint32_t)strlen(msg)) != APP_OK) {
        fprintf(stderr, "[OBU] send appdata failed\n");
        net_close(fd);
        return -1;
    }
    printf("[OBU] sent APP_TEXT\n");

    uint16_t app_type = 0;
    uint8_t buf[1024];
    uint32_t buf_len = 0;
    if (pqtls_recv_appdata(fd, &sess, &app_type, buf, sizeof(buf), &buf_len) != APP_OK) {
        fprintf(stderr, "[OBU] recv appdata failed\n");
        net_close(fd);
        return -1;
    }
    printf("[OBU] recv app_type=0x%04x, len=%u\n", app_type, buf_len);
    if (app_type == PQTLS_APP_TEXT) {
        printf("[OBU] text: %.*s\n", (int)buf_len, (const char *)buf);
    }

    net_close(fd);
    scloud_global_cleanup();
    return 0;
}
