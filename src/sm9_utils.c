#include "sm9_utils.h"
#include <string.h>

// ====== 占位实现（演示期先跑协议，后续接 GmSSL）======

static uint8_t g_dummy_mpk[64] = {0xA5}; // demo

int sm9_master_init(void) {
    // 真实实现：调用 GmSSL 生成 SM9 master key（MSK/MPK），持久化 MPK/保护 MSK
    memset(g_dummy_mpk, 0xA5, sizeof(g_dummy_mpk));
    return APP_OK;
}

int sm9_issue_prv_for_id(const char *id, uint8_t *prv_out, uint32_t *prv_len) {
    if (!id || !prv_out || !prv_len || *prv_len < 64) return APP_ERR;
    // 真实实现：用 MSK 对 id 做 Extract，得到用户私钥
    memset(prv_out, 0x5A, 64);
    *prv_len = 64;
    return APP_OK;
}

int sm9_get_mpk(uint8_t *mpk_out, uint32_t *mpk_len) {
    if (!mpk_out || !mpk_len || *mpk_len < sizeof(g_dummy_mpk)) return APP_ERR;
    memcpy(mpk_out, g_dummy_mpk, sizeof(g_dummy_mpk));
    *mpk_len = sizeof(g_dummy_mpk);
    return APP_OK;
}

int sm9_sign(const char *id, const uint8_t *user_prv, uint32_t prv_len,
             const uint8_t *msg, uint32_t msg_len,
             uint8_t *sig, uint32_t *sig_len)
{
    if (!id || !user_prv || !msg || !sig || !sig_len || *sig_len < 32) return APP_ERR;
    // 真实实现：SM9 签名（GmSSL）
    // 占位：输出 32 字节“签名”
    memset(sig, 0x3C, 32);
    *sig_len = 32;
    return APP_OK;
}

int sm9_verify(const char *id, const uint8_t *mpk, uint32_t mpk_len,
               const uint8_t *msg, uint32_t msg_len,
               const uint8_t *sig, uint32_t sig_len)
{
    if (!id || !mpk || !msg || !sig) return APP_ERR;
    // 真实实现：SM9 验签（GmSSL）
    // 占位：总返回成功
    return APP_OK;
}

