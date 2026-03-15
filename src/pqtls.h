#ifndef PQTLS_H
#define PQTLS_H

#include <stdint.h>
#include <stdbool.h>

#include "common.h"
#include "pqtls_defs.h"

/**
 * @file pqtls.h
 * @brief PQTLS 对外接口与会话结构定义。
 */

typedef struct {
    /* 角色：true=客户端(Client)，false=服务端(Server) */
    bool is_client;

    /* 双方身份（UTF-8 字节串，不含 '\0'） */
    uint8_t client_id[ID_MAX_LEN];
    uint16_t client_id_len;
    uint8_t server_id[ID_MAX_LEN];
    uint16_t server_id_len;

    /* 握手随机数 */
    uint8_t client_random[PQTLS_RANDOM_LEN];
    uint8_t server_random[PQTLS_RANDOM_LEN];

    /* 协商结果 */
    uint8_t kem_id;
    uint8_t aead_id;
    uint8_t hash_id;

    /* KEM 共享秘密（SCloud+ 输出） */
    uint8_t k_pqc[64];
    uint32_t k_pqc_len;

    /* 应用数据方向密钥（SM4-GCM） */
    uint8_t app_key_c2s[PQTLS_SM4_KEYLEN];
    uint8_t app_iv_c2s[PQTLS_GCM_IVLEN];
    uint8_t app_key_s2c[PQTLS_SM4_KEYLEN];
    uint8_t app_iv_s2c[PQTLS_GCM_IVLEN];

    /* record 序号（每个方向单调递增） */
    uint64_t send_seq;
    uint64_t recv_seq;
} PQTLS_Session;

typedef struct {
    /* 本端身份 ID（UTF-8） */
    const char *local_id_utf8;

    /* 期望的对端身份 ID（UTF-8） */
    const char *peer_id_utf8;

    /* 本端 SM9 签名私钥路径 */
    const char *local_sign_key_path;
} PQTLS_EndpointConfig;

/**
 * @brief 客户端（Client）发起 PQTLS 握手，成功后 sess 中填充密钥与参数
 */
int pqtls_client_handshake(int fd, const char *client_id_utf8, const char *expected_server_id_utf8,
                           PQTLS_Session *sess);

/**
 * @brief 客户端（Client）按自定义身份与私钥路径发起握手
 */
int pqtls_client_handshake_with_config(int fd, const PQTLS_EndpointConfig *config, PQTLS_Session *sess);

/**
 * @brief 服务端（Server）执行 PQTLS 握手，成功后 sess 中填充密钥与参数
 */
int pqtls_server_handshake(int fd, const char *expected_client_id_utf8, const char *server_id_utf8,
                           PQTLS_Session *sess);

/**
 * @brief 服务端（Server）按自定义身份与私钥路径执行握手
 */
int pqtls_server_handshake_with_config(int fd, const PQTLS_EndpointConfig *config, PQTLS_Session *sess);

/**
 * @brief 在已建立的安全会话上发送应用数据（REC_APPDATA）
 */
int pqtls_send_appdata(int fd, PQTLS_Session *sess, uint16_t app_type, const uint8_t *payload, uint32_t payload_len);

/**
 * @brief 在已建立的安全会话上接收应用数据（REC_APPDATA）
 */
int pqtls_recv_appdata(int fd, PQTLS_Session *sess, uint16_t *app_type, uint8_t *payload, uint32_t payload_cap,
                       uint32_t *payload_len);

#endif /* PQTLS_H */
