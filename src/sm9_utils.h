#ifndef SM9_UTILS_H
#define SM9_UTILS_H
#include <stdint.h>
#include "net.h"
#include <gmssl/sm9.h>
#include "common.h"

// 初始化/加载 SM9 主密钥对（MSK/MPK）
int sm9_master_init(void);
int sm9_issue_prv_for_id(const char *id);
int load_sm9_sign_key(SM9_SIGN_KEY *msk);
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *msk);
int sign_message(uint8_t *msg, size_t msg_len, uint8_t *sig, 
                size_t *sig_len, SM9_SIGN_KEY *user_key);
int verify_signature(uint8_t *msg, size_t msg_len, uint8_t *signature, 
                        size_t sig_len, SM9_SIGN_MASTER_KEY *mpk, char *user_id);
// 构建hello消息
int generate_message_hello(uint8_t *msg,uint32_t *length,const char *user_id,SM9_SIGN_KEY *user_key);

// 解析hello消息
int parse_message_hello(uint8_t *msg, size_t msg_len, char *user_id, SM9_SIGN_MASTER_KEY *mpk);


#endif
