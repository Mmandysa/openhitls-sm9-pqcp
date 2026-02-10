#ifndef PQTLS_SM9_AUTH_H
#define PQTLS_SM9_AUTH_H

#include <stdint.h>

#include <gmssl/sm9.h>

#include "pqtls_defs.h"

/**
 * @file pqtls_sm9_auth.h
 * @brief PQTLS 的 SM9 认证封装：对 transcript hash 做域分离签名/验签。
 *
 * 规划文档要求：
 * - sig_input = "PQTLS-SM9-SCLOUDPLUS" || 0x00 || role_byte || thash
 * - signature = SM9_Sign(SK_sig(SIGN_ID), sig_input)
 * - verify    = SM9_Verify(MPK, SIGN_ID, sig_input, signature)
 */

/**
 * @brief 对 transcript hash 生成 SM9_CERT_VERIFY 签名（输出原始签名字节串）
 * @return 0 成功；<0 失败
 */
int pqtls_sm9_sign_cert_verify(PQTLS_Role role, const uint8_t thash[PQTLS_SM3_LEN],
                               uint8_t *sig, uint32_t *sig_len,
                               const SM9_SIGN_KEY *sign_key);

/**
 * @brief 验证 SM9_CERT_VERIFY 签名
 * @return 0 成功；<0 失败
 */
int pqtls_sm9_verify_cert_verify(PQTLS_Role role, const uint8_t thash[PQTLS_SM3_LEN],
                                 const uint8_t *sig, uint32_t sig_len,
                                 const SM9_SIGN_MASTER_KEY *mpk,
                                 const char *signer_id_utf8);

#endif /* PQTLS_SM9_AUTH_H */

