#include "net.h"
#include "pqtls.h"
#include "scloud_kem.h"
#include "sm9_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog)
{
    printf("Usage: %s [client_id] [client_sign_key_path] [expected_server_id] [host] [port]\n", prog);
    printf("Default vehicle-cloud profile:\n");
    printf("  client_id          = %s\n", PQTLS_DEMO_DEVICE_DID);
    printf("  client_sign_key    = %s\n", SM9_DID_SIGN_KEY_PATH);
    printf("  expected_server_id = %s\n", PQTLS_DEMO_CLOUD_SID);
    printf("  host               = 127.0.0.1\n");
    printf("  port               = %d\n", DEFAULT_PORT);
    printf("Vehicle-RSU example:\n");
    printf("  %s %s %s %s 127.0.0.1 %d\n",
           prog,
           PQTLS_DEMO_DEVICE_PID_SLOT_A,
           SM9_PID_SLOT_A_SIGN_KEY_PATH,
           PQTLS_DEMO_RSU_RID,
           DEFAULT_PORT);
}

/**
 * @brief Client（客户端）演示入口：执行 PQTLS 握手，并在加密通道内收发一条 APP_TEXT
 */
int main(int argc, char **argv)
{
    const char *client_id = PQTLS_DEMO_DEVICE_DID;
    const char *client_sign_key_path = SM9_DID_SIGN_KEY_PATH;
    const char *expected_server_id = PQTLS_DEMO_CLOUD_SID;
    const char *host = "127.0.0.1";
    int port = DEFAULT_PORT;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc > 1) client_id = argv[1];
    if (argc > 2) client_sign_key_path = argv[2];
    if (argc > 3) expected_server_id = argv[3];
    if (argc > 4) host = argv[4];
    if (argc > 5) port = atoi(argv[5]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %d\n", port);
        return -1;
    }

    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n");
        return -1;
    }

    printf("[CLIENT] local_id=%s\n", client_id);
    printf("[CLIENT] local_sign_key=%s\n", client_sign_key_path);
    printf("[CLIENT] expected_server_id=%s\n", expected_server_id);
    printf("[CLIENT] peer=%s:%d\n", host, port);

    int fd = net_connect(host, port);
    if (fd < 0) {
        perror("connect");
        return -1;
    }
    printf("[CLIENT] connected\n");

    PQTLS_Session sess;
    PQTLS_EndpointConfig config = {
        .local_id_utf8 = client_id,
        .peer_id_utf8 = expected_server_id,
        .local_sign_key_path = client_sign_key_path,
    };
    if (pqtls_client_handshake_with_config(fd, &config, &sess) != APP_OK) {
        fprintf(stderr, "[CLIENT] handshake FAILED\n");
        net_close(fd);
        return -1;
    }
    printf("[CLIENT] handshake OK\n");

    const char *msg = "Hello server, this is client (PQTLS + SM9 + SCloud+).";
    if (pqtls_send_appdata(fd, &sess, PQTLS_APP_TEXT, (const uint8_t *)msg, (uint32_t)strlen(msg)) != APP_OK) {
        fprintf(stderr, "[CLIENT] send appdata failed\n");
        net_close(fd);
        return -1;
    }
    printf("[CLIENT] sent APP_TEXT\n");

    uint16_t app_type = 0;
    uint8_t buf[1024];
    uint32_t buf_len = 0;
    if (pqtls_recv_appdata(fd, &sess, &app_type, buf, sizeof(buf), &buf_len) != APP_OK) {
        fprintf(stderr, "[CLIENT] recv appdata failed\n");
        net_close(fd);
        return -1;
    }
    printf("[CLIENT] recv app_type=0x%04x, len=%u\n", app_type, buf_len);
    if (app_type == PQTLS_APP_TEXT) {
        printf("[CLIENT] text: %.*s\n", (int)buf_len, (const char *)buf);
    }

    net_close(fd);
    scloud_global_cleanup();
    return 0;
}
