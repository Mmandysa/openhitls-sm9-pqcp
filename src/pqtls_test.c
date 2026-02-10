#include "pqtls.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "pqtls_crypto.h"
#include "net.h"
#include "scloud_kem.h"
#include "sm9_utils.h"

/**
 * @file pqtls_test.c
 * @brief PQTLS 端到端自测：在同一进程内用 socketpair 模拟客户端/服务端握手，并打印密钥用于比对。
 *
 * 说明：
 * - 本测试会输出握手派生出的关键材料（k_pqc / app_key / app_iv），仅用于调试与验收；
 *   生产环境严禁打印或记录密钥。
 */

typedef struct {
    int listen_fd;
    const char *expected_client_id;
    const char *server_id;
    PQTLS_Session *sess;
    int handshake_result;
    int appdata_result;
} ServerThreadArgs;

/**
 * @brief 打印十六进制数据（单行）
 */
static void print_hex_line(const char *label, const uint8_t *data, uint32_t len)
{
    printf("%s (len=%u): ", label, len);
    for (uint32_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/**
 * @brief 打印会话关键材料（用于双方比对）
 */
static void print_session_keys(const char *who, const PQTLS_Session *sess)
{
    printf("========== [%s] PQTLS Session ==========\n", who);
    printf("role: %s\n", sess->is_client ? "client" : "server");
    printf("client_id: %.*s\n", (int)sess->client_id_len, (const char *)sess->client_id);
    printf("server_id: %.*s\n", (int)sess->server_id_len, (const char *)sess->server_id);
    printf("kem_id=0x%02x aead_id=0x%02x hash_id=0x%02x\n", sess->kem_id, sess->aead_id, sess->hash_id);

    print_hex_line("client_random", sess->client_random, PQTLS_RANDOM_LEN);
    print_hex_line("server_random", sess->server_random, PQTLS_RANDOM_LEN);

    print_hex_line("k_pqc", sess->k_pqc, sess->k_pqc_len);

    uint8_t dgst[PQTLS_SM3_LEN];
    if (pqtls_sm3(sess->k_pqc, sess->k_pqc_len, dgst) == 0) {
        print_hex_line("SM3(k_pqc)", dgst, PQTLS_SM3_LEN);
    }

    print_hex_line("app_key_c2s", sess->app_key_c2s, PQTLS_SM4_KEYLEN);
    print_hex_line("app_iv_c2s", sess->app_iv_c2s, PQTLS_GCM_IVLEN);
    print_hex_line("app_key_s2c", sess->app_key_s2c, PQTLS_SM4_KEYLEN);
    print_hex_line("app_iv_s2c", sess->app_iv_s2c, PQTLS_GCM_IVLEN);
    printf("========================================\n");
}

/**
 * @brief 测试前确保 SM9 签名密钥材料存在，不存在则自动生成
 */
static int ensure_sm9_test_keys(const char *obu_id, const char *rsu_id)
{
    if (access(SM9_SIGN_MPK_PATH, R_OK) == 0 &&
        access(SM9_OBU_SIGN_KEY_PATH, R_OK) == 0 &&
        access(SM9_RSU_SIGN_KEY_PATH, R_OK) == 0) {
        return APP_OK;
    }

    printf("[TEST] SM9 keys not found, generating keys into keys/ ...\n");
    if (sm9_master_init() != APP_OK) return APP_ERR;
    if (sm9_issue_prv_for_id(obu_id, SM9_OBU_SIGN_KEY_PATH) != APP_OK) return APP_ERR;
    if (sm9_issue_prv_for_id(rsu_id, SM9_RSU_SIGN_KEY_PATH) != APP_OK) return APP_ERR;
    return APP_OK;
}

/**
 * @brief 服务端线程入口：执行 PQTLS 服务端握手
 */
static void *server_thread_main(void *arg)
{
    ServerThreadArgs *a = (ServerThreadArgs *)arg;

    int cfd = net_accept(a->listen_fd);
    if (cfd < 0) {
        perror("accept");
        a->handshake_result = APP_ERR;
        a->appdata_result = APP_ERR;
        return NULL;
    }

    a->handshake_result = pqtls_server_handshake(cfd, a->expected_client_id, a->server_id, a->sess);
    a->appdata_result = APP_ERR;
    if (a->handshake_result == APP_OK) {
        /* 握手成功后，收一条消息再回一条，验证 record 层可用 */
        uint16_t app_type = 0;
        uint8_t buf[1024];
        uint32_t buf_len = 0;
        if (pqtls_recv_appdata(cfd, a->sess, &app_type, buf, sizeof(buf), &buf_len) == APP_OK) {
            printf("[TEST][SERVER] got app_type=0x%04x, text=%.*s\n", app_type, (int)buf_len, (const char *)buf);
            const char *resp = "PQTLS test resp: server -> client";
            if (pqtls_send_appdata(cfd, a->sess, PQTLS_APP_TEXT, (const uint8_t *)resp, (uint32_t)strlen(resp)) == APP_OK) {
                a->appdata_result = APP_OK;
            } else {
                fprintf(stderr, "[TEST][SERVER] send appdata failed\n");
            }
        } else {
            fprintf(stderr, "[TEST][SERVER] recv appdata failed\n");
        }
    }

    net_close(cfd);
    return NULL;
}

/**
 * @brief 程序入口：并行跑握手 + 打印密钥 + 发送加密应用数据做验证
 */
int main(void)
{
    const char *obu_id = "琼B12345";
    const char *rsu_id = "RSU_001";

    /* 1) 初始化 PQCP provider（SCloud+） */
    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "[TEST] PQCP provider init failed\n");
        return 1;
    }

    /* 2) 确保 SM9 签名密钥存在 */
    if (ensure_sm9_test_keys(obu_id, rsu_id) != APP_OK) {
        fprintf(stderr, "[TEST] ensure SM9 keys failed\n");
        return 1;
    }

    /* 3) 启动本地 TCP server（使用端口 0 让系统分配空闲端口） */
    int lfd = net_listen(0);
    if (lfd < 0) {
        perror("listen");
        return 1;
    }

    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) {
        perror("getsockname");
        net_close(lfd);
        return 1;
    }
    uint16_t port = ntohs(addr.sin_port);
    printf("[TEST] listen on 127.0.0.1:%u\n", port);

    PQTLS_Session client_sess;
    PQTLS_Session server_sess;
    memset(&client_sess, 0, sizeof(client_sess));
    memset(&server_sess, 0, sizeof(server_sess));

    ServerThreadArgs sargs = {.listen_fd = lfd, .expected_client_id = obu_id, .server_id = rsu_id, .sess = &server_sess,
                              .handshake_result = APP_ERR, .appdata_result = APP_ERR};

    pthread_t st;
    if (pthread_create(&st, NULL, server_thread_main, &sargs) != 0) {
        fprintf(stderr, "[TEST] pthread_create(server) failed\n");
        return 1;
    }

    /* 4) 客户端连接并握手（主线程） */
    int cfd = net_connect("127.0.0.1", port);
    if (cfd < 0) {
        perror("connect");
        (void)shutdown(lfd, SHUT_RDWR);
        net_close(lfd);
        (void)pthread_join(st, NULL);
        return 1;
    }

    int cret = pqtls_client_handshake(cfd, obu_id, rsu_id, &client_sess);
    if (cret != APP_OK) {
        fprintf(stderr, "[TEST] client handshake failed: %d\n", cret);
        (void)shutdown(cfd, SHUT_RDWR);
    }

    /* 5) 握手成功后，发一条再收一条，验证 record 层 */
    int ok = 1;
    if (cret == APP_OK) {
        const char *msg1 = "PQTLS test msg: client -> server";
        if (pqtls_send_appdata(cfd, &client_sess, PQTLS_APP_TEXT, (const uint8_t *)msg1, (uint32_t)strlen(msg1)) != APP_OK) {
            fprintf(stderr, "[TEST] client send appdata failed\n");
            ok = 0;
        }

        uint16_t t = 0;
        uint8_t buf[1024];
        uint32_t l = 0;
        if (pqtls_recv_appdata(cfd, &client_sess, &t, buf, sizeof(buf), &l) != APP_OK) {
            fprintf(stderr, "[TEST] client recv appdata failed\n");
            ok = 0;
        } else {
            printf("[TEST][CLIENT] got app_type=0x%04x, text=%.*s\n", t, (int)l, (const char *)buf);
        }
    }

    net_close(cfd);
    (void)pthread_join(st, NULL);

    if (cret != APP_OK || sargs.handshake_result != APP_OK) {
        fprintf(stderr, "[TEST] handshake failed: client=%d server=%d\n", cret, sargs.handshake_result);
        net_close(lfd);
        return 2;
    }

    printf("[TEST] handshake OK (client & server)\n");
    printf("[TEST] appdata: client=%s server=%s\n", ok ? "OK" : "FAIL", (sargs.appdata_result == APP_OK) ? "OK" : "FAIL");

    /* 4) 打印双方密钥材料并比对 */
    print_session_keys("CLIENT", &client_sess);
    print_session_keys("SERVER", &server_sess);

    if (client_sess.k_pqc_len != server_sess.k_pqc_len ||
        memcmp(client_sess.k_pqc, server_sess.k_pqc, client_sess.k_pqc_len) != 0) {
        fprintf(stderr, "[TEST] k_pqc mismatch!\n");
        ok = 0;
    }
    if (memcmp(client_sess.app_key_c2s, server_sess.app_key_c2s, PQTLS_SM4_KEYLEN) != 0 ||
        memcmp(client_sess.app_iv_c2s, server_sess.app_iv_c2s, PQTLS_GCM_IVLEN) != 0 ||
        memcmp(client_sess.app_key_s2c, server_sess.app_key_s2c, PQTLS_SM4_KEYLEN) != 0 ||
        memcmp(client_sess.app_iv_s2c, server_sess.app_iv_s2c, PQTLS_GCM_IVLEN) != 0) {
        fprintf(stderr, "[TEST] app keys mismatch!\n");
        ok = 0;
    }
    printf("[TEST] key compare: %s\n", ok ? "MATCH" : "MISMATCH");
    net_close(lfd);
    scloud_global_cleanup();

    return ok ? 0 : 3;
}
