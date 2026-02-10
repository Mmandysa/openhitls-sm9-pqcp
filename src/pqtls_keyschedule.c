#include "pqtls_keyschedule.h"

#include <string.h>

#include "pqtls_crypto.h"

/**
 * @brief 使用 label||thash 构造 HKDF-Expand 的 info，并输出指定长度的 key material
 */
static int hkdf_expand_with_label(const uint8_t prk[PQTLS_SM3_LEN], const char *label,
                                  const uint8_t thash[PQTLS_SM3_LEN], uint8_t *out, uint32_t out_len)
{
    if (!prk || !label || !thash || !out) return -1;

    uint8_t info[128];
    size_t label_len = strlen(label);
    if (label_len + PQTLS_SM3_LEN > sizeof(info)) return -1;

    memcpy(info, label, label_len);
    memcpy(info + label_len, thash, PQTLS_SM3_LEN);

    return pqtls_hkdf_expand_sm3(prk, info, (uint32_t)(label_len + PQTLS_SM3_LEN), out, out_len);
}

/**
 * @brief 派生 finished_key 与 record 层应用密钥/IV（双向）
 */
int pqtls_derive_secrets(const uint8_t *k_pqc, uint32_t k_pqc_len,
                         const uint8_t client_random[PQTLS_RANDOM_LEN],
                         const uint8_t server_random[PQTLS_RANDOM_LEN],
                         const uint8_t thash_key[PQTLS_SM3_LEN],
                         uint8_t out_finished_key_c2s[PQTLS_SM3_LEN],
                         uint8_t out_finished_key_s2c[PQTLS_SM3_LEN],
                         uint8_t out_app_key_c2s[PQTLS_SM4_KEYLEN],
                         uint8_t out_app_iv_c2s[PQTLS_GCM_IVLEN],
                         uint8_t out_app_key_s2c[PQTLS_SM4_KEYLEN],
                         uint8_t out_app_iv_s2c[PQTLS_GCM_IVLEN])
{
    if (!k_pqc || k_pqc_len == 0) return -1;
    if (!client_random || !server_random || !thash_key) return -1;
    if (!out_finished_key_c2s || !out_finished_key_s2c) return -1;
    if (!out_app_key_c2s || !out_app_iv_c2s || !out_app_key_s2c || !out_app_iv_s2c) return -1;

    /* salt = SM3("PQTLS-salt" || client_random || server_random) */
    static const char salt_label[] = "PQTLS-salt";
    uint8_t salt_in[sizeof(salt_label) - 1 + PQTLS_RANDOM_LEN + PQTLS_RANDOM_LEN];
    uint32_t off = 0;
    memcpy(salt_in + off, salt_label, sizeof(salt_label) - 1); off += (uint32_t)(sizeof(salt_label) - 1);
    memcpy(salt_in + off, client_random, PQTLS_RANDOM_LEN); off += PQTLS_RANDOM_LEN;
    memcpy(salt_in + off, server_random, PQTLS_RANDOM_LEN); off += PQTLS_RANDOM_LEN;

    uint8_t salt[PQTLS_SM3_LEN];
    if (pqtls_sm3(salt_in, off, salt) != 0) return -1;

    /* PRK = HKDF-Extract(salt, k_pqc) */
    uint8_t prk[PQTLS_SM3_LEN];
    if (pqtls_hkdf_extract_sm3(salt, sizeof(salt), k_pqc, k_pqc_len, prk) != 0) return -1;

    /* finished_key / app_key / app_iv 派生 */
    if (hkdf_expand_with_label(prk, "finished c2s", thash_key, out_finished_key_c2s, PQTLS_SM3_LEN) != 0) return -1;
    if (hkdf_expand_with_label(prk, "finished s2c", thash_key, out_finished_key_s2c, PQTLS_SM3_LEN) != 0) return -1;

    if (hkdf_expand_with_label(prk, "key c2s", thash_key, out_app_key_c2s, PQTLS_SM4_KEYLEN) != 0) return -1;
    if (hkdf_expand_with_label(prk, "iv c2s", thash_key, out_app_iv_c2s, PQTLS_GCM_IVLEN) != 0) return -1;
    if (hkdf_expand_with_label(prk, "key s2c", thash_key, out_app_key_s2c, PQTLS_SM4_KEYLEN) != 0) return -1;
    if (hkdf_expand_with_label(prk, "iv s2c", thash_key, out_app_iv_s2c, PQTLS_GCM_IVLEN) != 0) return -1;

    pqtls_secure_clear(prk, sizeof(prk));
    pqtls_secure_clear(salt, sizeof(salt));
    return 0;
}

/**
 * @brief 计算 Finished.verify_data = HMAC-SM3(finished_key, thash)
 */
int pqtls_calc_finished_verify_data(const uint8_t finished_key[PQTLS_SM3_LEN],
                                    const uint8_t thash[PQTLS_SM3_LEN],
                                    uint8_t out_verify_data[PQTLS_SM3_LEN])
{
    if (!finished_key || !thash || !out_verify_data) return -1;
    return pqtls_hmac_sm3(finished_key, PQTLS_SM3_LEN, thash, PQTLS_SM3_LEN, out_verify_data);
}
