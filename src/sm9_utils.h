#ifndef SM9_UTILS_H
#define SM9_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <gmssl/sm9.h>

/**
 * @file sm9_utils.h
 * @brief SM9（签名）相关的密钥管理与签名/验签封装。
 *
 * 说明：
 * - 本项目的“身份认证”采用 SM9 签名。
 * - SM9 签名私钥由 TMC 离线颁发并写入 pem 文件，运行时从文件加载。
 */

/* 密钥文件路径（相对项目根目录运行时的工作目录） */
#define SM9_SIGN_MSK_PATH      "keys/sm9_sign_master_key.pem"
#define SM9_SIGN_MPK_PATH      "keys/sm9_sign_master_public.pem"
#define SM9_CLIENT_SIGN_KEY_PATH  "keys/sm9_client_sign_key.pem"
#define SM9_SERVER_SIGN_KEY_PATH  "keys/sm9_server_sign_key.pem"

/* 兼容旧命名（OBU/RSU） */
#define SM9_OBU_SIGN_KEY_PATH SM9_CLIENT_SIGN_KEY_PATH
#define SM9_RSU_SIGN_KEY_PATH SM9_SERVER_SIGN_KEY_PATH

/* PEM 加密口令（演示用，生产环境应替换成安全的密钥保护方案） */
#define SM9_KEY_PASSWORD "pqtls_demo_password"

/* =========================
 * 密钥生成/颁发（通常由 setup_keys 工具调用）
 * ========================= */

/**
 * @brief 生成 SM9 签名主密钥对（MSK/MPK），并写入 pem 文件
 */
int sm9_master_init(void);

/**
 * @brief 为指定 ID 颁发 SM9 签名私钥，并写入 pem 文件
 */
int sm9_issue_prv_for_id(const char *id, const char *filepath);

/* =========================
 * 运行时加载
 * ========================= */

/**
 * @brief 从文件加载 SM9 签名私钥（pem）
 */
int load_sm9_sign_key_from_file(SM9_SIGN_KEY *key, const char *filepath);

/**
 * @brief 从文件加载 SM9 签名主公钥（pem）
 */
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *mpk);

/* =========================
 * 签名/验签
 * ========================= */

/**
 * @brief SM9 对 msg 做签名，输出 signature
 */
int sign_message(const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len, const SM9_SIGN_KEY *user_key);

/**
 * @brief 验证签名：用 (MPK + user_id) 验证 signature
 */
int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *signature, size_t sig_len,
                     const SM9_SIGN_MASTER_KEY *mpk, const char *user_id);

#endif /* SM9_UTILS_H */
