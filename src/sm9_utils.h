#ifndef SM9_UTILS_H
#define SM9_UTILS_H
#include <stdint.h>
#include <gmssl/sm9.h>
#include "common.h"

// 初始化/加载 SM9 主密钥对（MSK/MPK）
int sm9_master_init(void);
int sm9_issue_prv_for_id(const char *id);
int load_sm9_sign_key(SM9_SIGN_KEY *msk);
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *msk) ;

#endif
