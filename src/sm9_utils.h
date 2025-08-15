#ifndef SM9_UTILS_H
#define SM9_UTILS_H
#include <stdint.h>
#include "common.h"

// 初始化/加载 SM9 主密钥对（MSK/MPK）
int sm9_master_init(void);
int sm9_issue_prv_for_id(const char *id, uint8_t *prv_out, uint32_t *prv_len);
int sm9_get_mpk(uint8_t *mpk_out, uint32_t *mpk_len);

// 基于 transcript 的签名/验签（身份即公钥，id 作为公钥标识）
int sm9_sign(const char *id, const uint8_t *user_prv, uint32_t prv_len,
             const uint8_t *msg, uint32_t msg_len,
             uint8_t *sig, uint32_t *sig_len);

int sm9_verify(const char *id, const uint8_t *mpk, uint32_t mpk_len,
               const uint8_t *msg, uint32_t msg_len,
               const uint8_t *sig, uint32_t sig_len);

#endif
