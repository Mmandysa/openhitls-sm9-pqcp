#ifndef SM9_UTILS_H
#define SM9_UTILS_H
#include <stdint.h>
#include "net.h"
#include <gmssl/sm9.h>
#include "common.h"
#define SIGN_MSK_PATH     "sm9_sign_master_key.pem"
#define SIGN_MPK_PATH     "sm9_sign_master_public.pem"
#define OBU_SIGN_KEY_PATH "sm9_obu_sign_key.pem"

// --- 新增：加密/交换密钥文件 ---
#define ENC_MSK_PATH "sm9_enc_master_key.pem"
#define ENC_MPK_PATH "sm9_enc_master_public.pem"
#define OBU_ENC_KEY_PATH "sm9_obu_enc_key.pem"
#define RSU_ENC_KEY_PATH "sm9_rsu_enc_key.pem"
// src/sm9_utils.h (最终修正版)

// --- 密钥生成与管理 ---
int sm9_master_init(void);
int sm9_issue_prv_for_id(const char *id, const char* filepath);
int sm9_enc_master_init(void);
int sm9_issue_enc_prv_for_id(const char *id, const char* filepath);

// --- 密钥加载 ---
int load_sm9_sign_key(SM9_SIGN_KEY *key);
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *mpk);
int load_sm9_enc_master_pub_key(SM9_ENC_MASTER_KEY *mpk);
int load_sm9_enc_key(SM9_ENC_KEY *key,char *filepath);
// --- 签名与验证 ---
int sign_message(uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len, SM9_SIGN_KEY *user_key);
int verify_signature(uint8_t *msg, size_t msg_len, uint8_t *signature, size_t sig_len, SM9_SIGN_MASTER_KEY *mpk, char *user_id);

// --- 消息处理 (*** 关键修改 ***) ---
int generate_message_hello(uint8_t *msg, uint32_t *length, 
                           const char *sign_id, const char *exch_id, // 两个ID
                           SM9_SIGN_KEY *user_key, const SM9_Z256_POINT *RA);

int parse_message_hello(uint8_t *msg, size_t msg_len, 
                        char *sign_id, char *exch_id, // 两个ID
                        SM9_SIGN_MASTER_KEY *mpk, SM9_Z256_POINT *RA);


// --- 顶层函数声明保持不变 ---
int sm9_kex_obu_start(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, const char *rsu_id, SM9_Z256_POINT *RA);
int sm9_kex_rsu_respond(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, SM9_ENC_KEY *key, const char *obu_id, const char *rsu_id, const SM9_Z256_POINT *RA, SM9_Z256_POINT *RB);
int sm9_kex_obu_finish(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, SM9_ENC_KEY *key, const char *obu_id, const char *rsu_id, const SM9_Z256_POINT *RA, const SM9_Z256_POINT *RB);

// --- 辅助函数 ---
int gen_nonce(uint8_t *nonce, uint32_t len);

#endif // SM9_UTILS_H