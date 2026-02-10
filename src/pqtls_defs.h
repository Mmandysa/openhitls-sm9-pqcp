#ifndef PQTLS_DEFS_H
#define PQTLS_DEFS_H

#include <stdint.h>

/**
 * @file pqtls_defs.h
 * @brief PQTLS（自定义 TLS-like 协议）的常量/枚举定义。
 *
 * 说明：
 * - 本项目在 TCP 之上自定义 record 与 handshake 格式（包结构由我们自己定义）。
 * - 非对称/身份相关只使用 SM9（认证）与 SCloud+（KEM）。
 * - 对称、哈希、HMAC 等基础原语通过 openHiTLS 的 CRYPT_EAL_* 接口调用（SM3/SM4-GCM 等）。
 */

/* =========================
 * 版本号
 * ========================= */
#define PQTLS_VERSION_V1 0x0001u

/* =========================
 * 外层 Record 类型（对应 net_send_packet 的 type 字段）
 * ========================= */
typedef enum {
    PQTLS_REC_HANDSHAKE   = 0x0001,
    PQTLS_REC_APPDATA     = 0x0002,
    PQTLS_REC_ALERT_PLAIN = 0x0003,
} PQTLS_RecordType;

/* =========================
 * Handshake 消息类型（record 内部）
 * ========================= */
typedef enum {
    PQTLS_HS_CLIENT_HELLO     = 0x01,
    PQTLS_HS_SERVER_HELLO     = 0x02,
    PQTLS_HS_CLIENT_KEM       = 0x03,
    PQTLS_HS_SM9_CERT_VERIFY  = 0x0F,
    PQTLS_HS_FINISHED         = 0x14,
} PQTLS_HandshakeType;

/* =========================
 * TLV 类型（handshake body 内部）
 * ========================= */
typedef enum {
    PQTLS_TLV_VERSION         = 0x0001,
    PQTLS_TLV_RANDOM          = 0x0002,
    PQTLS_TLV_SIGN_ID         = 0x0003,

    PQTLS_TLV_SUPPORTED_KEM   = 0x0010,
    PQTLS_TLV_SELECTED_KEM    = 0x0011,
    PQTLS_TLV_KEM_PUBKEY      = 0x0012,
    PQTLS_TLV_KEM_CIPHERTEXT  = 0x0013,

    PQTLS_TLV_SUPPORTED_AEAD  = 0x0020,
    PQTLS_TLV_SELECTED_AEAD   = 0x0021,

    PQTLS_TLV_SUPPORTED_HASH  = 0x0030,
    PQTLS_TLV_SELECTED_HASH   = 0x0031,

    PQTLS_TLV_SIGNATURE       = 0x00F0,
    PQTLS_TLV_SIG_ROLE        = 0x00F1,
    PQTLS_TLV_VERIFY_DATA     = 0x00F2,

    PQTLS_TLV_EXT             = 0x7FFF,
} PQTLS_TlvType;

/* =========================
 * 算法标识（协商字段的值）
 * ========================= */
typedef enum {
    PQTLS_KEM_SCLOUDPLUS_128 = 0x01,
    PQTLS_KEM_SCLOUDPLUS_192 = 0x02,
    PQTLS_KEM_SCLOUDPLUS_256 = 0x03,
} PQTLS_KemId;

typedef enum {
    PQTLS_AEAD_SM4_GCM_128 = 0x01,
} PQTLS_AeadId;

typedef enum {
    PQTLS_HASH_SM3 = 0x01,
} PQTLS_HashId;

/* =========================
 * 其他常量
 * ========================= */
#define PQTLS_RANDOM_LEN 32u
#define PQTLS_SM3_LEN    32u
#define PQTLS_GCM_TAGLEN 16u
#define PQTLS_SM4_KEYLEN 16u
#define PQTLS_GCM_IVLEN  12u

/* SM9 签名的域分离字符串（ASCII） */
#define PQTLS_SM9_SIG_DOMAIN "PQTLS-SM9-SCLOUDPLUS"

/* =========================
 * 应用层（加密后明文）消息类型
 * ========================= */
#define PQTLS_APP_PING       0x0001u
#define PQTLS_APP_TEXT       0x0002u
#define PQTLS_APP_VEH_STATUS 0x0101u
#define PQTLS_APP_ALERT      0xFF01u

/* SM9_CERT_VERIFY/FINISHED 中的 role 取值 */
typedef enum {
    PQTLS_ROLE_CLIENT = 0,
    PQTLS_ROLE_SERVER = 1,
} PQTLS_Role;

#endif /* PQTLS_DEFS_H */
