#include "pqtls_crypto.h"

#include <string.h>
#include <stdlib.h>

#include "crypto/crypt_eal_md.h"
#include "crypto/crypt_eal_mac.h"
#include "crypto/crypt_algid.h"
#include "crypto/crypt_errno.h"

#define PQTLS_SM3_LEN 32u

/**
 * @brief 计算 SM3(data) -> out(32 bytes)
 */
int pqtls_sm3(const uint8_t *data, uint32_t len, uint8_t out[32])
{
    if (!out) return -1;
    if (!data && len != 0) return -1;

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    if (!ctx) return -1;

    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) goto err;

    if (len != 0) {
        ret = CRYPT_EAL_MdUpdate(ctx, data, len);
        if (ret != CRYPT_SUCCESS) goto err;
    }

    uint32_t out_len = PQTLS_SM3_LEN;
    ret = CRYPT_EAL_MdFinal(ctx, out, &out_len);
    if (ret != CRYPT_SUCCESS || out_len != PQTLS_SM3_LEN) goto err;

    CRYPT_EAL_MdFreeCtx(ctx);
    return 0;
err:
    CRYPT_EAL_MdFreeCtx(ctx);
    return -1;
}

/**
 * @brief 计算 HMAC-SM3(key, data) -> out(32 bytes)
 */
int pqtls_hmac_sm3(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, uint8_t out[32])
{
    if (!out) return -1;
    if (!key && key_len != 0) return -1;
    if (!data && data_len != 0) return -1;

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SM3);
    if (!ctx) return -1;

    int32_t ret = CRYPT_EAL_MacInit(ctx, key, key_len);
    if (ret != CRYPT_SUCCESS) goto err;

    if (data_len != 0) {
        ret = CRYPT_EAL_MacUpdate(ctx, data, data_len);
        if (ret != CRYPT_SUCCESS) goto err;
    }

    uint32_t out_len = PQTLS_SM3_LEN;
    ret = CRYPT_EAL_MacFinal(ctx, out, &out_len);
    if (ret != CRYPT_SUCCESS || out_len != PQTLS_SM3_LEN) goto err;

    CRYPT_EAL_MacFreeCtx(ctx);
    return 0;
err:
    CRYPT_EAL_MacFreeCtx(ctx);
    return -1;
}

/**
 * @brief HKDF-Extract（SM3）：PRK = HMAC-SM3(salt, IKM)
 */
int pqtls_hkdf_extract_sm3(const uint8_t *salt, uint32_t salt_len, const uint8_t *ikm, uint32_t ikm_len,
                           uint8_t out_prk[32])
{
    if (!out_prk) return -1;
    if (!ikm && ikm_len != 0) return -1;

    /* RFC5869: 若 salt 为空，则使用 HashLen 个 0 作为 key */
    uint8_t zero_key[PQTLS_SM3_LEN];
    const uint8_t *key = salt;
    uint32_t key_len = salt_len;
    if (!salt || salt_len == 0) {
        memset(zero_key, 0, sizeof(zero_key));
        key = zero_key;
        key_len = (uint32_t)sizeof(zero_key);
    }
    return pqtls_hmac_sm3(key, key_len, ikm, ikm_len, out_prk);
}

/**
 * @brief HKDF-Expand（SM3）：OKM = HKDF-Expand(PRK, info, L)
 */
int pqtls_hkdf_expand_sm3(const uint8_t prk[32], const uint8_t *info, uint32_t info_len, uint8_t *okm,
                          uint32_t okm_len)
{
    if (!prk || !okm) return -1;
    if (!info && info_len != 0) return -1;
    if (okm_len == 0) return 0;

    /* RFC5869: N = ceil(L/HashLen) */
    uint32_t hash_len = PQTLS_SM3_LEN;
    uint32_t n = (okm_len + hash_len - 1u) / hash_len;
    if (n == 0 || n > 255u) return -1;

    uint8_t t[PQTLS_SM3_LEN];
    uint32_t t_len = 0;
    uint32_t out_off = 0;

    for (uint32_t i = 1; i <= n; i++) {
        /* HMAC(PRK, T(i-1) || info || i) */
        uint8_t buf[1024];
        uint32_t need = t_len + info_len + 1u;
        uint8_t *dyn = NULL;
        uint8_t *in = buf;
        if (need > sizeof(buf)) {
            dyn = (uint8_t *)malloc(need);
            if (!dyn) return -1;
            in = dyn;
        }

        uint32_t off = 0;
        if (t_len != 0) { memcpy(in + off, t, t_len); off += t_len; }
        if (info_len != 0) { memcpy(in + off, info, info_len); off += info_len; }
        in[off++] = (uint8_t)i;

        if (pqtls_hmac_sm3(prk, PQTLS_SM3_LEN, in, off, t) != 0) {
            if (dyn) { pqtls_secure_clear(dyn, need); free(dyn); }
            return -1;
        }
        if (dyn) { pqtls_secure_clear(dyn, need); free(dyn); }

        t_len = hash_len;
        uint32_t copy = (okm_len - out_off < hash_len) ? (okm_len - out_off) : hash_len;
        memcpy(okm + out_off, t, copy);
        out_off += copy;
    }

    pqtls_secure_clear(t, sizeof(t));
    return 0;
}

/**
 * @brief 常量时间比较（用于比较 tag/verify_data 等）
 */
int pqtls_ct_memcmp(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    if (!a || !b) return -1;
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff;
}

/**
 * @brief 安全清理敏感数据（尽量避免被编译器优化掉）
 */
void pqtls_secure_clear(void *p, uint32_t len)
{
    if (!p || len == 0) return;
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (uint32_t i = 0; i < len; i++) vp[i] = 0;
}
