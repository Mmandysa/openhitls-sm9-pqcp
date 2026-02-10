#include "pqtls_sm9_auth.h"

#include <string.h>

#include "pqtls_defs.h"
#include "common.h"
#include "sm9_utils.h"

/**
 * @brief 构造 SM9_CERT_VERIFY 的签名输入（sig_input）
 * @return 0 成功；<0 失败
 */
static int build_sig_input(PQTLS_Role role, const uint8_t thash[PQTLS_SM3_LEN], uint8_t *out, uint32_t out_cap,
                           uint32_t *out_len)
{
    if (!thash || !out || !out_len) return -1;

    const char *domain = PQTLS_SM9_SIG_DOMAIN;
    size_t domain_len = strlen(domain);
    size_t need = domain_len + 1u + 1u + PQTLS_SM3_LEN;
    if (need > out_cap) return -1;

    memcpy(out, domain, domain_len);
    out[domain_len] = 0x00;
    out[domain_len + 1] = (uint8_t)role;
    memcpy(out + domain_len + 2, thash, PQTLS_SM3_LEN);

    *out_len = (uint32_t)need;
    return 0;
}

/**
 * @brief 对 transcript hash 生成 SM9_CERT_VERIFY 签名（输出原始签名字节串）
 */
int pqtls_sm9_sign_cert_verify(PQTLS_Role role, const uint8_t thash[PQTLS_SM3_LEN],
                               uint8_t *sig, uint32_t *sig_len,
                               const SM9_SIGN_KEY *sign_key)
{
    if (!thash || !sig || !sig_len || !sign_key) return -1;

    uint8_t sig_input[128];
    uint32_t sig_input_len = 0;
    if (build_sig_input(role, thash, sig_input, sizeof(sig_input), &sig_input_len) != 0) return -1;

    size_t out_len = *sig_len;
    if (sign_message(sig_input, sig_input_len, sig, &out_len, sign_key) != APP_OK) return -1;
    if (out_len > UINT32_MAX) return -1;
    *sig_len = (uint32_t)out_len;
    return 0;
}

/**
 * @brief 验证 SM9_CERT_VERIFY 签名
 */
int pqtls_sm9_verify_cert_verify(PQTLS_Role role, const uint8_t thash[PQTLS_SM3_LEN],
                                 const uint8_t *sig, uint32_t sig_len,
                                 const SM9_SIGN_MASTER_KEY *mpk,
                                 const char *signer_id_utf8)
{
    if (!thash || !sig || sig_len == 0 || !mpk || !signer_id_utf8) return -1;

    uint8_t sig_input[128];
    uint32_t sig_input_len = 0;
    if (build_sig_input(role, thash, sig_input, sizeof(sig_input), &sig_input_len) != 0) return -1;

    if (verify_signature(sig_input, sig_input_len, sig, sig_len, mpk, signer_id_utf8) != APP_OK) return -1;
    return 0;
}
