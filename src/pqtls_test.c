#include "pqtls.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "pqtls_codec.h"
#include "pqtls_crypto.h"
#include "pqtls_defs.h"
#include "net.h"
#include "scloud_kem.h"
#include "sm9_utils.h"

/**
 * @file pqtls_test.c
 * @brief PQTLS 端到端自测：本地回环建立 client/server，会话握手 + record 层收发验证，并“抓包”打印每帧/每字段含义。
 *
 * 说明：
 * - 本测试会输出握手派生出的关键材料（k_pqc / app_key / app_iv），仅用于调试与验收；
 *   生产环境严禁打印或记录密钥。
 */

/* =========================
 * 抓包打印（sniffer/proxy）
 * ========================= */

/**
 * @brief 全局日志互斥锁：避免双向转发线程的打印交错
 */
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int listen_fd;
    const char *expected_client_id;
    const char *server_id;
    PQTLS_Session *sess;
    int handshake_result;
    int appdata_result;
} ServerThreadArgs;

typedef struct {
    int listen_fd;
    uint16_t upstream_port; /* 服务端真实端口 */
    int proxy_result;
} ProxyThreadArgs;

typedef struct {
    const char *dir; /* "C->S" or "S->C" */
    int src_fd;
    int dst_fd;
} ForwardThreadArgs;

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
 * @brief 打印十六进制数据（对较长数据只打印前缀，避免刷屏）
 */
static void print_hex_trunc(const char *label, const uint8_t *data, uint32_t len, uint32_t max_print)
{
    if (!label) label = "(null)";
    if (!data && len != 0) {
        printf("%s: <null>\n", label);
        return;
    }
    if (max_print == 0) max_print = 32;

    printf("%s (len=%u): ", label, len);
    uint32_t n = (len <= max_print) ? len : max_print;
    for (uint32_t i = 0; i < n; i++) printf("%02x", data[i]);
    if (len > max_print) printf("...(+%u bytes)", len - max_print);
    printf("\n");
}

/**
 * @brief 记录类型 -> 可读字符串
 */
static const char *rec_type_str(uint16_t t)
{
    switch (t) {
        case PQTLS_REC_HANDSHAKE: return "PQTLS_REC_HANDSHAKE(握手明文记录)";
        case PQTLS_REC_APPDATA: return "PQTLS_REC_APPDATA(应用数据加密记录)";
        case PQTLS_REC_ALERT_PLAIN: return "PQTLS_REC_ALERT_PLAIN(明文告警)";
        default: return "UNKNOWN_RECORD";
    }
}

/**
 * @brief 握手消息类型 -> 可读字符串
 */
static const char *hs_type_str(uint8_t t)
{
    switch (t) {
        case PQTLS_HS_CLIENT_HELLO: return "CLIENT_HELLO";
        case PQTLS_HS_SERVER_HELLO: return "SERVER_HELLO";
        case PQTLS_HS_CLIENT_KEM: return "CLIENT_KEM";
        case PQTLS_HS_SM9_CERT_VERIFY: return "SM9_CERT_VERIFY";
        case PQTLS_HS_FINISHED: return "FINISHED";
        default: return "UNKNOWN_HS";
    }
}

/**
 * @brief 握手消息类型 -> 中文含义
 */
static const char *hs_type_meaning(uint8_t t)
{
    switch (t) {
        case PQTLS_HS_CLIENT_HELLO:
            return "客户端发起握手：携带版本/随机数/身份ID/支持算法列表";
        case PQTLS_HS_SERVER_HELLO:
            return "服务端响应：携带版本/随机数/身份ID/选择的算法/KEM公钥";
        case PQTLS_HS_CLIENT_KEM:
            return "客户端KEM封装：发送KEM密文，服务端解封装得到共享秘密k_pqc";
        case PQTLS_HS_SM9_CERT_VERIFY:
            return "SM9身份认证：对握手transcript_hash做SM9签名，证明持有对应ID的私钥";
        case PQTLS_HS_FINISHED:
            return "握手完成校验：verify_data=HMAC-SM3(finished_key, transcript_hash)";
        default:
            return "未知握手消息";
    }
}

/**
 * @brief TLV 类型 -> 可读字符串
 */
static const char *tlv_type_str(uint16_t t)
{
    switch (t) {
        case PQTLS_TLV_VERSION: return "VERSION(协议版本)";
        case PQTLS_TLV_RANDOM: return "RANDOM(握手随机数)";
        case PQTLS_TLV_SIGN_ID: return "SIGN_ID(签名/身份ID)";
        case PQTLS_TLV_SUPPORTED_KEM: return "SUPPORTED_KEM(支持的KEM列表)";
        case PQTLS_TLV_SELECTED_KEM: return "SELECTED_KEM(选择的KEM)";
        case PQTLS_TLV_KEM_PUBKEY: return "KEM_PUBKEY(KEM公钥)";
        case PQTLS_TLV_KEM_CIPHERTEXT: return "KEM_CIPHERTEXT(KEM密文)";
        case PQTLS_TLV_SUPPORTED_AEAD: return "SUPPORTED_AEAD(支持的AEAD列表)";
        case PQTLS_TLV_SELECTED_AEAD: return "SELECTED_AEAD(选择的AEAD)";
        case PQTLS_TLV_SUPPORTED_HASH: return "SUPPORTED_HASH(支持的HASH列表)";
        case PQTLS_TLV_SELECTED_HASH: return "SELECTED_HASH(选择的HASH)";
        case PQTLS_TLV_SIGNATURE: return "SIGNATURE(SM9签名)";
        case PQTLS_TLV_SIG_ROLE: return "SIG_ROLE(签名/Finished所属角色)";
        case PQTLS_TLV_VERIFY_DATA: return "VERIFY_DATA(Finished校验值)";
        case PQTLS_TLV_EXT: return "EXT(扩展/保留)";
        default: return "UNKNOWN_TLV";
    }
}

/**
 * @brief KEM 算法ID -> 可读字符串
 */
static const char *kem_id_str(uint8_t id)
{
    switch (id) {
        case PQTLS_KEM_SCLOUDPLUS_128: return "SCLOUDPLUS_128";
        case PQTLS_KEM_SCLOUDPLUS_192: return "SCLOUDPLUS_192";
        case PQTLS_KEM_SCLOUDPLUS_256: return "SCLOUDPLUS_256";
        default: return "UNKNOWN_KEM";
    }
}

/**
 * @brief AEAD 算法ID -> 可读字符串
 */
static const char *aead_id_str(uint8_t id)
{
    switch (id) {
        case PQTLS_AEAD_SM4_GCM_128: return "SM4-GCM-128";
        default: return "UNKNOWN_AEAD";
    }
}

/**
 * @brief HASH 算法ID -> 可读字符串
 */
static const char *hash_id_str(uint8_t id)
{
    switch (id) {
        case PQTLS_HASH_SM3: return "SM3";
        default: return "UNKNOWN_HASH";
    }
}

/**
 * @brief role -> 可读字符串
 */
static const char *role_str(uint8_t role)
{
    switch (role) {
        case PQTLS_ROLE_CLIENT: return "CLIENT";
        case PQTLS_ROLE_SERVER: return "SERVER";
        default: return "UNKNOWN_ROLE";
    }
}

/**
 * @brief app_type -> 可读字符串
 */
static const char *app_type_str(uint16_t t)
{
    switch (t) {
        case PQTLS_APP_PING: return "APP_PING";
        case PQTLS_APP_TEXT: return "APP_TEXT";
        case PQTLS_APP_VEH_STATUS: return "APP_VEH_STATUS";
        case PQTLS_APP_ALERT: return "APP_ALERT";
        default: return "APP_UNKNOWN";
    }
}

/**
 * @brief 打印一个 TLV 的 value（按类型解释含义）
 */
static void print_tlv_value(const char *dir, int hs_idx, int tlv_idx, uint8_t hs_type, const PQTLS_Tlv *tlv)
{
    if (!tlv) return;

    const uint8_t *v = tlv->v;
    uint16_t l = tlv->l;

    switch (tlv->t) {
        case PQTLS_TLV_VERSION: {
            if (l == 2) {
                uint16_t ver = pqtls_read_u16(v);
                printf("[WIRE][%s][HS#%d][TLV#%d] value=0x%04x (%s) - 协议版本\n",
                       dir, hs_idx, tlv_idx, ver, (ver == PQTLS_VERSION_V1) ? "PQTLS_VERSION_V1" : "未知版本");
            } else {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=<bad len %u> - VERSION应为2字节\n",
                       dir, hs_idx, tlv_idx, (unsigned)l);
            }
            break;
        }
        case PQTLS_TLV_RANDOM: {
            const char *who = (hs_type == PQTLS_HS_CLIENT_HELLO) ? "client_random" :
                              (hs_type == PQTLS_HS_SERVER_HELLO) ? "server_random" : "random";
            print_hex_line("[WIRE] RANDOM", v, l);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: %s，用于salt/密钥派生与防重放\n",
                   dir, hs_idx, tlv_idx, who);
            break;
        }
        case PQTLS_TLV_SIGN_ID: {
            printf("[WIRE][%s][HS#%d][TLV#%d] value=\"%.*s\" - 对端声明的身份ID(UTF-8)，也用于SM9验签的ID\n",
                   dir, hs_idx, tlv_idx, (int)l, (const char *)v);
            break;
        }
        case PQTLS_TLV_SUPPORTED_KEM:
        case PQTLS_TLV_SUPPORTED_AEAD:
        case PQTLS_TLV_SUPPORTED_HASH: {
            const char *what = (tlv->t == PQTLS_TLV_SUPPORTED_KEM) ? "KEM" :
                               (tlv->t == PQTLS_TLV_SUPPORTED_AEAD) ? "AEAD" : "HASH";
            printf("[WIRE][%s][HS#%d][TLV#%d] value(list of %s, %u bytes):\n",
                   dir, hs_idx, tlv_idx, what, (unsigned)l);
            for (uint16_t i = 0; i < l; i++) {
                uint8_t id = v[i];
                const char *name = (tlv->t == PQTLS_TLV_SUPPORTED_KEM) ? kem_id_str(id) :
                                   (tlv->t == PQTLS_TLV_SUPPORTED_AEAD) ? aead_id_str(id) : hash_id_str(id);
                printf("  - [%u] 0x%02x (%s)\n", (unsigned)i, id, name);
            }
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: 该端支持的%s算法列表\n", dir, hs_idx, tlv_idx, what);
            break;
        }
        case PQTLS_TLV_SELECTED_KEM:
        case PQTLS_TLV_SELECTED_AEAD:
        case PQTLS_TLV_SELECTED_HASH: {
            if (l != 1) {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=<bad len %u> - 该字段应为1字节算法ID\n",
                       dir, hs_idx, tlv_idx, (unsigned)l);
                break;
            }
            uint8_t id = v[0];
            if (tlv->t == PQTLS_TLV_SELECTED_KEM) {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=0x%02x (%s) - 服务端选择的KEM\n",
                       dir, hs_idx, tlv_idx, id, kem_id_str(id));
            } else if (tlv->t == PQTLS_TLV_SELECTED_AEAD) {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=0x%02x (%s) - 服务端选择的AEAD\n",
                       dir, hs_idx, tlv_idx, id, aead_id_str(id));
            } else {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=0x%02x (%s) - 服务端选择的HASH\n",
                       dir, hs_idx, tlv_idx, id, hash_id_str(id));
            }
            break;
        }
        case PQTLS_TLV_KEM_PUBKEY: {
            print_hex_trunc("[WIRE] KEM_PUBKEY", v, l, 48);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: 服务端SCloud+ KEM公钥(只打印前缀)\n",
                   dir, hs_idx, tlv_idx);
            break;
        }
        case PQTLS_TLV_KEM_CIPHERTEXT: {
            print_hex_trunc("[WIRE] KEM_CIPHERTEXT", v, l, 48);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: 客户端KEM封装输出密文(只打印前缀)\n",
                   dir, hs_idx, tlv_idx);
            break;
        }
        case PQTLS_TLV_SIG_ROLE: {
            if (l != 1) {
                printf("[WIRE][%s][HS#%d][TLV#%d] value=<bad len %u> - SIG_ROLE应为1字节\n",
                       dir, hs_idx, tlv_idx, (unsigned)l);
                break;
            }
            uint8_t role = v[0];
            printf("[WIRE][%s][HS#%d][TLV#%d] value=%u (%s) - 表示该认证/Finished属于哪一方\n",
                   dir, hs_idx, tlv_idx, (unsigned)role, role_str(role));
            break;
        }
        case PQTLS_TLV_SIGNATURE: {
            print_hex_trunc("[WIRE] SIGNATURE", v, l, 48);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: SM9签名(对transcript_hash做签名并绑定role)(只打印前缀)\n",
                   dir, hs_idx, tlv_idx);
            break;
        }
        case PQTLS_TLV_VERIFY_DATA: {
            print_hex_line("[WIRE] VERIFY_DATA", v, l);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: HMAC-SM3(finished_key, transcript_hash)\n",
                   dir, hs_idx, tlv_idx);
            break;
        }
        default: {
            print_hex_trunc("[WIRE] TLV_VALUE", v, l, 32);
            printf("[WIRE][%s][HS#%d][TLV#%d] 含义: 未知/扩展字段，按原样转发并忽略\n",
                   dir, hs_idx, tlv_idx);
            break;
        }
    }
}

/**
 * @brief 打印一个握手 record：解析 payload 中的多条握手消息，并逐字段打印
 */
static void print_handshake_record(const char *dir, const uint8_t *payload, uint32_t payload_len)
{
    printf("[WIRE][%s] HANDSHAKE payload_len=%u (可能包含多条握手消息)\n", dir, payload_len);

    uint32_t off = 0;
    int hs_idx = 0;
    while (off < payload_len) {
        uint8_t hs_type = 0;
        const uint8_t *hs_body = NULL;
        uint32_t hs_body_len = 0;
        const uint8_t *hs_bytes = NULL;
        uint32_t hs_bytes_len = 0;
        if (pqtls_hs_decode_next(payload, payload_len, &off, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) {
            printf("[WIRE][%s] 解析握手消息失败：off=%u payload_len=%u\n", dir, off, payload_len);
            return;
        }

        printf("[WIRE][%s][HS#%d] hs_type=0x%02x (%s), hs_len=%u (body长度)\n",
               dir, hs_idx, hs_type, hs_type_str(hs_type), hs_body_len);
        printf("[WIRE][%s][HS#%d] 含义: %s\n", dir, hs_idx, hs_type_meaning(hs_type));

        /* 解析 TLV 列表 */
        uint32_t toff = 0;
        int tlv_idx = 0;
        while (toff < hs_body_len) {
            PQTLS_Tlv tlv;
            if (pqtls_tlv_next(hs_body, hs_body_len, &toff, &tlv) != 0) {
                printf("[WIRE][%s][HS#%d] 解析TLV失败：toff=%u body_len=%u\n", dir, hs_idx, toff, hs_body_len);
                break;
            }
            printf("[WIRE][%s][HS#%d][TLV#%d] t=0x%04x (%s), l=%u\n",
                   dir, hs_idx, tlv_idx, tlv.t, tlv_type_str(tlv.t), (unsigned)tlv.l);
            print_tlv_value(dir, hs_idx, tlv_idx, hs_type, &tlv);
            tlv_idx++;
        }
        hs_idx++;
        (void)hs_bytes;
        (void)hs_bytes_len;
    }
}

/**
 * @brief 打印一个应用数据 record（加密态）：payload=seq(8)||ciphertext||tag(16)
 */
static void print_appdata_record(const char *dir, const uint8_t *payload, uint32_t payload_len)
{
    printf("[WIRE][%s] APPDATA payload_len=%u\n", dir, payload_len);
    if (payload_len < 8u + PQTLS_GCM_TAGLEN) {
        printf("[WIRE][%s] APPDATA格式错误：payload_len过小\n", dir);
        return;
    }
    uint64_t seq = pqtls_read_u64(payload);
    uint32_t ct_len = payload_len - 8u - PQTLS_GCM_TAGLEN;
    const uint8_t *ct = payload + 8;
    const uint8_t *tag = payload + 8 + ct_len;

    printf("[WIRE][%s][APPDATA] seq=%llu - 记录序号(用于nonce派生与重放保护)\n",
           dir, (unsigned long long)seq);
    printf("[WIRE][%s][APPDATA] ciphertext_len=%u - 密文长度(不含seq与tag)\n", dir, ct_len);
    print_hex_trunc("[WIRE] ciphertext(prefix)", ct, ct_len, 48);
    print_hex_line("[WIRE] tag(GCM)", tag, PQTLS_GCM_TAGLEN);
    printf("[WIRE][%s][APPDATA] 含义: payload = seq(8) || SM4-GCM(ciphertext) || tag(16)\n", dir);
}

/**
 * @brief 打印一帧（PacketHeader + payload），并按 record 类型解析字段
 */
static void print_wire_frame(const char *dir, uint16_t rec_type, const uint8_t *payload, uint32_t payload_len)
{
    printf("------------------------------------------------------------\n");
    printf("[WIRE][%s] PacketHeader.type=0x%04x (%s)\n", dir, rec_type, rec_type_str(rec_type));
    printf("[WIRE][%s] PacketHeader.len=%u (payload字节数)\n", dir, payload_len);

    if (rec_type == PQTLS_REC_HANDSHAKE) {
        print_handshake_record(dir, payload, payload_len);
    } else if (rec_type == PQTLS_REC_APPDATA) {
        print_appdata_record(dir, payload, payload_len);
    } else {
        /* 其他 record：直接打印前缀 */
        print_hex_trunc("[WIRE] payload(prefix)", payload, payload_len, 64);
    }
    printf("------------------------------------------------------------\n");
}

/**
 * @brief 单向转发线程：读取一帧 -> 打印字段 -> 原样转发到对端
 */
static void *forward_thread_main(void *arg)
{
    ForwardThreadArgs *a = (ForwardThreadArgs *)arg;
    uint8_t payload[MAX_PAYLOAD];

    for (;;) {
        PacketHeader h;
        if (net_recv_all(a->src_fd, &h, (int)sizeof(h)) != (int)sizeof(h)) break;
        uint16_t type = ntohs(h.type);
        uint32_t len = ntohl(h.len);
        if (len > sizeof(payload)) break;
        if (len != 0) {
            if (net_recv_all(a->src_fd, payload, (int)len) != (int)len) break;
        }

        pthread_mutex_lock(&g_log_mu);
        print_wire_frame(a->dir, type, payload, len);
        pthread_mutex_unlock(&g_log_mu);

        if (net_send_all(a->dst_fd, &h, (int)sizeof(h)) != (int)sizeof(h)) break;
        if (len != 0) {
            if (net_send_all(a->dst_fd, payload, (int)len) != (int)len) break;
        }
    }

    (void)shutdown(a->dst_fd, SHUT_RDWR);
    (void)shutdown(a->src_fd, SHUT_RDWR);
    return NULL;
}

/**
 * @brief 代理线程入口：接受 client 连接，再连接到 server，并启动双向转发(抓包打印)
 */
static void *proxy_thread_main(void *arg)
{
    ProxyThreadArgs *a = (ProxyThreadArgs *)arg;
    a->proxy_result = APP_ERR;

    int cfd = net_accept(a->listen_fd);
    if (cfd < 0) {
        perror("[PROXY] accept");
        return NULL;
    }

    int sfd = net_connect("127.0.0.1", (int)a->upstream_port);
    if (sfd < 0) {
        perror("[PROXY] connect upstream");
        net_close(cfd);
        return NULL;
    }

    ForwardThreadArgs c2s = {.dir = "C->S", .src_fd = cfd, .dst_fd = sfd};
    ForwardThreadArgs s2c = {.dir = "S->C", .src_fd = sfd, .dst_fd = cfd};

    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, forward_thread_main, &c2s) != 0) {
        fprintf(stderr, "[PROXY] pthread_create(c2s) failed\n");
        net_close(cfd);
        net_close(sfd);
        return NULL;
    }
    if (pthread_create(&t2, NULL, forward_thread_main, &s2c) != 0) {
        fprintf(stderr, "[PROXY] pthread_create(s2c) failed\n");
        (void)shutdown(cfd, SHUT_RDWR);
        (void)shutdown(sfd, SHUT_RDWR);
        (void)pthread_join(t1, NULL);
        net_close(cfd);
        net_close(sfd);
        return NULL;
    }

    (void)pthread_join(t1, NULL);
    (void)pthread_join(t2, NULL);
    net_close(cfd);
    net_close(sfd);
    a->proxy_result = APP_OK;
    return NULL;
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
static int ensure_sm9_test_keys(const char *client_id, const char *server_id)
{
    if (access(SM9_SIGN_MPK_PATH, R_OK) == 0 &&
        access(SM9_CLIENT_SIGN_KEY_PATH, R_OK) == 0 &&
        access(SM9_SERVER_SIGN_KEY_PATH, R_OK) == 0) {
        return APP_OK;
    }

    printf("[TEST] SM9 keys not found, generating keys into keys/ ...\n");
    if (sm9_master_init() != APP_OK) return APP_ERR;
    if (sm9_issue_prv_for_id(client_id, SM9_CLIENT_SIGN_KEY_PATH) != APP_OK) return APP_ERR;
    if (sm9_issue_prv_for_id(server_id, SM9_SERVER_SIGN_KEY_PATH) != APP_OK) return APP_ERR;
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
            printf("[TEST][SERVER] 解密后应用明文: app_type=0x%04x (%s), app_len=%u, text=%.*s\n",
                   app_type, app_type_str(app_type), buf_len, (int)buf_len, (const char *)buf);
            const char *resp = "PQTLS test resp: server -> client";
            printf("[TEST][SERVER] 发送应用明文: app_type=0x%04x (%s), app_len=%u\n",
                   PQTLS_APP_TEXT, app_type_str(PQTLS_APP_TEXT), (unsigned)strlen(resp));
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
    const char *client_id = "琼B12345";
    const char *server_id = "RSU_001";

    /* 1) 初始化 PQCP provider（SCloud+） */
    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        fprintf(stderr, "[TEST] PQCP provider init failed\n");
        return 1;
    }

    /* 2) 确保 SM9 签名密钥存在 */
    if (ensure_sm9_test_keys(client_id, server_id) != APP_OK) {
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

    /* 3.1) 启动代理（抓包打印）：client 连接到 proxy，proxy 再连接到真实 server */
    int pfd = net_listen(0);
    if (pfd < 0) {
        perror("proxy listen");
        net_close(lfd);
        return 1;
    }
    struct sockaddr_in paddr;
    socklen_t palen = sizeof(paddr);
    memset(&paddr, 0, sizeof(paddr));
    if (getsockname(pfd, (struct sockaddr *)&paddr, &palen) != 0) {
        perror("proxy getsockname");
        net_close(pfd);
        net_close(lfd);
        return 1;
    }
    uint16_t proxy_port = ntohs(paddr.sin_port);
    printf("[TEST] proxy listen on 127.0.0.1:%u (用于抓包打印)\n", proxy_port);

    PQTLS_Session client_sess;
    PQTLS_Session server_sess;
    memset(&client_sess, 0, sizeof(client_sess));
    memset(&server_sess, 0, sizeof(server_sess));

    ServerThreadArgs sargs = {.listen_fd = lfd, .expected_client_id = client_id, .server_id = server_id, .sess = &server_sess,
                              .handshake_result = APP_ERR, .appdata_result = APP_ERR};

    pthread_t st;
    if (pthread_create(&st, NULL, server_thread_main, &sargs) != 0) {
        fprintf(stderr, "[TEST] pthread_create(server) failed\n");
        return 1;
    }

    ProxyThreadArgs pargs = {.listen_fd = pfd, .upstream_port = port, .proxy_result = APP_ERR};
    pthread_t pt;
    if (pthread_create(&pt, NULL, proxy_thread_main, &pargs) != 0) {
        fprintf(stderr, "[TEST] pthread_create(proxy) failed\n");
        (void)shutdown(lfd, SHUT_RDWR);
        net_close(pfd);
        net_close(lfd);
        (void)pthread_join(st, NULL);
        return 1;
    }

    /* 4) 客户端连接 proxy 并握手（主线程） */
    int cfd = net_connect("127.0.0.1", proxy_port);
    if (cfd < 0) {
        perror("connect");
        (void)shutdown(lfd, SHUT_RDWR);
        (void)shutdown(pfd, SHUT_RDWR);
        net_close(pfd);
        net_close(lfd);
        (void)pthread_join(pt, NULL);
        (void)pthread_join(st, NULL);
        return 1;
    }

    int cret = pqtls_client_handshake(cfd, client_id, server_id, &client_sess);
    if (cret != APP_OK) {
        fprintf(stderr, "[TEST] client handshake failed: %d\n", cret);
        (void)shutdown(cfd, SHUT_RDWR);
    }

    /* 5) 握手成功后，发一条再收一条，验证 record 层 */
    int ok = 1;
    if (cret == APP_OK) {
        const char *msg1 = "PQTLS test msg: client -> server";
        printf("[TEST][CLIENT] 发送应用明文: app_type=0x%04x (%s), app_len=%u\n",
               PQTLS_APP_TEXT, app_type_str(PQTLS_APP_TEXT), (unsigned)strlen(msg1));
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
            printf("[TEST][CLIENT] 解密后应用明文: app_type=0x%04x (%s), app_len=%u, text=%.*s\n",
                   t, app_type_str(t), l, (int)l, (const char *)buf);
        }
    }

    net_close(cfd);
    (void)pthread_join(st, NULL);
    (void)pthread_join(pt, NULL);

    if (cret != APP_OK || sargs.handshake_result != APP_OK) {
        fprintf(stderr, "[TEST] handshake failed: client=%d server=%d\n", cret, sargs.handshake_result);
        net_close(pfd);
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
    net_close(pfd);
    net_close(lfd);
    scloud_global_cleanup();

    return ok ? 0 : 3;
}
