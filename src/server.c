#include "net.h"
#include "pqtls.h"
#include "scloud_kem.h"
#include "sm9_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog)
{
    printf("Usage: %s [server_id] [server_sign_key_path] [expected_client_id] [port]\n", prog);
    printf("Default vehicle-cloud profile:\n");
    printf("  server_id          = %s\n", PQTLS_DEMO_CLOUD_SID);
    printf("  server_sign_key    = %s\n", SM9_SID_SIGN_KEY_PATH);
    printf("  expected_client_id = %s\n", PQTLS_DEMO_DEVICE_DID);
    printf("  port               = %d\n", DEFAULT_PORT);
    printf("Vehicle-RSU example:\n");
    printf("  %s %s %s %s %d\n",
           prog,
           PQTLS_DEMO_RSU_RID,
           SM9_RID_SIGN_KEY_PATH,
           PQTLS_DEMO_DEVICE_PID_SLOT_A,
           DEFAULT_PORT);
}

/**
 * @brief Server（服务端）演示入口：执行 PQTLS 握手，并在加密通道内收发一条 APP_TEXT
 */
int main(int argc, char **argv)
{
    const char *server_id = PQTLS_DEMO_CLOUD_SID;
    const char *server_sign_key_path = SM9_SID_SIGN_KEY_PATH;
    const char *expected_client_id = PQTLS_DEMO_DEVICE_DID;
    int port = DEFAULT_PORT;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc > 1) server_id = argv[1];
    if (argc > 2) server_sign_key_path = argv[2];
    if (argc > 3) expected_client_id = argv[3];
    if (argc > 4) port = atoi(argv[4]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %d\n", port);
        return -1;
    }

    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "PQCP provider init failed\n");
        return -1;
    }

    printf("[SERVER] local_id=%s\n", server_id);
    printf("[SERVER] local_sign_key=%s\n", server_sign_key_path);
    printf("[SERVER] expected_client_id=%s\n", expected_client_id);
    printf("[SERVER] listen_port=%d\n", port);

    int lfd = net_listen(port);
    if (lfd < 0) {
        perror("listen");
        return -1;
    }
    printf("[SERVER] listening on %d...\n", port);

    int cfd = net_accept(lfd);
    if (cfd < 0) {
        perror("accept");
        net_close(lfd);
        return -1;
    }
    printf("[SERVER] client connected\n");

    PQTLS_Session sess;
    PQTLS_EndpointConfig config = {
        .local_id_utf8 = server_id,
        .peer_id_utf8 = expected_client_id,
        .local_sign_key_path = server_sign_key_path,
    };
    if (pqtls_server_handshake_with_config(cfd, &config, &sess) != APP_OK) {
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
