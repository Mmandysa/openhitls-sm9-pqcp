#include "pqtls_record.h"

#include <string.h>
#include <stdio.h>

#include "net.h"
#include "pqtls_codec.h"
#include "pqtls_crypto.h"
#include "pqtls_defs.h"

#include "crypto/crypt_eal_cipher.h"
#include "crypto/crypt_algid.h"
#include "crypto/crypt_errno.h"
#include "crypto/crypt_types.h"

/* =========================
 * 内部工具
 * ========================= */

/**
 * @brief 生成 SM4-GCM nonce：nonce = iv XOR (0x00000000 || seq_be64)
 */
static void make_gcm_nonce(uint8_t nonce[PQTLS_GCM_IVLEN], const uint8_t iv[PQTLS_GCM_IVLEN], uint64_t seq)
{
    uint8_t seq_buf[12];
    memset(seq_buf, 0, sizeof(seq_buf));
    pqtls_write_u64(seq_buf + 4, seq);
    for (uint32_t i = 0; i < PQTLS_GCM_IVLEN; i++) nonce[i] = (uint8_t)(iv[i] ^ seq_buf[i]);
}

/**
 * @brief 构造 AAD：uint16(rec_type) || uint64(seq) || uint32(ciphertext_len)
 */
static void make_aad(uint8_t aad[2 + 8 + 4], uint16_t rec_type, uint64_t seq, uint32_t ciphertext_len)
{
    pqtls_write_u16(aad, rec_type);
    pqtls_write_u64(aad + 2, seq);
    pqtls_write_u32(aad + 10, ciphertext_len);
}

/**
 * @brief SM4-GCM 加密：输入明文，输出密文与 tag
 */
static int sm4_gcm_encrypt(const uint8_t key[PQTLS_SM4_KEYLEN], const uint8_t iv[PQTLS_GCM_IVLEN], uint64_t seq,
                           const uint8_t *pt, uint32_t pt_len, uint8_t *ct, uint32_t ct_cap, uint32_t *ct_len,
                           uint8_t tag[PQTLS_GCM_TAGLEN])
{
    if (!key || !iv || (!pt && pt_len != 0) || !ct || !ct_len || !tag) return -1;
    if (pt_len > ct_cap) return -1;

    uint8_t nonce[PQTLS_GCM_IVLEN];
    make_gcm_nonce(nonce, iv, seq);

    uint8_t aad[2 + 8 + 4];
    make_aad(aad, PQTLS_REC_APPDATA, seq, pt_len);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_GCM);
    if (!ctx) return -1;

    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, PQTLS_SM4_KEYLEN, nonce, PQTLS_GCM_IVLEN, true);
    if (ret != CRYPT_SUCCESS) goto err;

    uint32_t taglen = PQTLS_GCM_TAGLEN;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &taglen, sizeof(taglen));
    if (ret != CRYPT_SUCCESS) goto err;

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, (uint32_t)sizeof(aad));
    if (ret != CRYPT_SUCCESS) goto err;

    uint32_t out_len = ct_cap;
    ret = CRYPT_EAL_CipherUpdate(ctx, pt, pt_len, ct, &out_len);
    if (ret != CRYPT_SUCCESS) goto err;

    /*
     * 注意：openHiTLS 的 AEAD（如 SM4-GCM）不需要也不支持 CRYPT_EAL_CipherFinal，
     * 调用 Final 会返回 CRYPT_EAL_CIPHER_FINAL_WITH_AEAD_ERROR。
     * 因此这里仅使用 CipherUpdate 完成加密，然后通过 GET_TAG 取出 tag。
     */

    /* 获取 tag */
    uint8_t tag_tmp[PQTLS_GCM_TAGLEN];
    memset(tag_tmp, 0, sizeof(tag_tmp));
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag_tmp, PQTLS_GCM_TAGLEN);
    if (ret != CRYPT_SUCCESS) goto err;
    memcpy(tag, tag_tmp, PQTLS_GCM_TAGLEN);
    pqtls_secure_clear(tag_tmp, sizeof(tag_tmp));

    *ct_len = out_len;
    CRYPT_EAL_CipherFreeCtx(ctx);
    return 0;
err:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return -1;
}

/**
 * @brief SM4-GCM 解密：输入密文与 tag，输出明文（同时校验 tag）
 */
static int sm4_gcm_decrypt(const uint8_t key[PQTLS_SM4_KEYLEN], const uint8_t iv[PQTLS_GCM_IVLEN], uint64_t seq,
                           const uint8_t *ct, uint32_t ct_len, const uint8_t tag[PQTLS_GCM_TAGLEN],
                           uint8_t *pt, uint32_t pt_cap, uint32_t *pt_len)
{
    if (!key || !iv || (!ct && ct_len != 0) || !tag || !pt || !pt_len) return -1;
    if (ct_len > pt_cap) return -1;

    uint8_t nonce[PQTLS_GCM_IVLEN];
    make_gcm_nonce(nonce, iv, seq);

    uint8_t aad[2 + 8 + 4];
    make_aad(aad, PQTLS_REC_APPDATA, seq, ct_len);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_GCM);
    if (!ctx) return -1;

    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, PQTLS_SM4_KEYLEN, nonce, PQTLS_GCM_IVLEN, false);
    if (ret != CRYPT_SUCCESS) goto err;

    uint32_t taglen = PQTLS_GCM_TAGLEN;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &taglen, sizeof(taglen));
    if (ret != CRYPT_SUCCESS) goto err;

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, (uint32_t)sizeof(aad));
    if (ret != CRYPT_SUCCESS) goto err;

    uint32_t out_len = pt_cap;
    ret = CRYPT_EAL_CipherUpdate(ctx, ct, ct_len, pt, &out_len);
    if (ret != CRYPT_SUCCESS) goto err;

    /*
     * 注意：同加密侧，AEAD 不需要/不支持 CipherFinal；tag 校验由我们取出 calc_tag 后自行比较完成。
     */

    /* 解密时同样可以取到计算出的 tag，与输入 tag 做常量时间比较 */
    uint8_t calc_tag[PQTLS_GCM_TAGLEN];
    memset(calc_tag, 0, sizeof(calc_tag));
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, calc_tag, PQTLS_GCM_TAGLEN);
    if (ret != CRYPT_SUCCESS) goto err;

    if (pqtls_ct_memcmp(calc_tag, tag, PQTLS_GCM_TAGLEN) != 0) {
        pqtls_secure_clear(calc_tag, sizeof(calc_tag));
        goto err;
    }
    pqtls_secure_clear(calc_tag, sizeof(calc_tag));

    *pt_len = out_len;
    CRYPT_EAL_CipherFreeCtx(ctx);
    return 0;
err:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return -1;
}

/* =========================
 * 对外接口
 * ========================= */

/**
 * @brief 发送一条加密的应用数据 record（REC_APPDATA）
 */
int pqtls_record_send_appdata(int fd, PQTLS_Session *sess, uint16_t app_type, const uint8_t *payload,
                              uint32_t payload_len)
{
    if (!sess || (!payload && payload_len != 0)) return APP_ERR;

    /* 1) 组装明文：app_type(2) + app_len(4) + payload */
    uint8_t pt[MAX_PAYLOAD];
    if (payload_len > (uint32_t)(sizeof(pt) - 6u)) return APP_ERR;
    pqtls_write_u16(pt, app_type);
    pqtls_write_u32(pt + 2, payload_len);
    if (payload_len != 0) memcpy(pt + 6, payload, payload_len);
    uint32_t pt_len = 6u + payload_len;

    /* 2) 选择方向密钥 */
    const uint8_t *key = sess->is_client ? sess->app_key_c2s : sess->app_key_s2c;
    const uint8_t *iv  = sess->is_client ? sess->app_iv_c2s  : sess->app_iv_s2c;

    /* 3) 加密 */
    uint8_t ct[MAX_PAYLOAD];
    uint32_t ct_len = 0;
    uint8_t tag[PQTLS_GCM_TAGLEN];
    if (sm4_gcm_encrypt(key, iv, sess->send_seq, pt, pt_len, ct, sizeof(ct), &ct_len, tag) != 0) return APP_ERR;

    /* 4) 组装 record payload：seq(8) + ciphertext + tag(16) */
    uint8_t rec[MAX_PAYLOAD];
    if (8u + ct_len + PQTLS_GCM_TAGLEN > sizeof(rec)) return APP_ERR;
    pqtls_write_u64(rec, sess->send_seq);
    memcpy(rec + 8, ct, ct_len);
    memcpy(rec + 8 + ct_len, tag, PQTLS_GCM_TAGLEN);
    uint32_t rec_len = 8u + ct_len + PQTLS_GCM_TAGLEN;

    /* 5) 发送 */
    if (net_send_packet(fd, PQTLS_REC_APPDATA, rec, rec_len) != APP_OK) return APP_ERR;
    sess->send_seq++;
    return APP_OK;
}

/**
 * @brief 接收一条加密的应用数据 record（REC_APPDATA）
 */
int pqtls_record_recv_appdata(int fd, PQTLS_Session *sess, uint16_t *app_type, uint8_t *payload, uint32_t payload_cap,
                              uint32_t *payload_len)
{
    if (!sess || !app_type || !payload || !payload_len) return APP_ERR;

    uint16_t rec_type = 0;
    uint8_t rec[MAX_PAYLOAD];
    uint32_t rec_len = 0;
    if (net_recv_packet(fd, &rec_type, rec, &rec_len, sizeof(rec)) != APP_OK) return APP_ERR;
    if (rec_type != PQTLS_REC_APPDATA) return APP_ERR;
    if (rec_len < 8u + PQTLS_GCM_TAGLEN) return APP_ERR;

    uint64_t seq = pqtls_read_u64(rec);
    if (seq != sess->recv_seq) {
        fprintf(stderr, "[PQTLS] 重放/乱序：expected_seq=%llu got=%llu\n",
                (unsigned long long)sess->recv_seq, (unsigned long long)seq);
        return APP_ERR;
    }

    uint32_t ct_len = rec_len - 8u - PQTLS_GCM_TAGLEN;
    const uint8_t *ct = rec + 8;
    const uint8_t *tag = rec + 8 + ct_len;

    /* 选择方向密钥（接收方向与发送相反） */
    const uint8_t *key = sess->is_client ? sess->app_key_s2c : sess->app_key_c2s;
    const uint8_t *iv  = sess->is_client ? sess->app_iv_s2c  : sess->app_iv_c2s;

    uint8_t pt[MAX_PAYLOAD];
    uint32_t pt_len = 0;
    if (sm4_gcm_decrypt(key, iv, seq, ct, ct_len, tag, pt, sizeof(pt), &pt_len) != 0) return APP_ERR;

    if (pt_len < 6u) return APP_ERR;
    uint16_t t = pqtls_read_u16(pt);
    uint32_t l = pqtls_read_u32(pt + 2);
    if (pt_len != 6u + l) return APP_ERR;
    if (l > payload_cap) return APP_ERR;
    if (l != 0) memcpy(payload, pt + 6, l);

    *app_type = t;
    *payload_len = l;
    sess->recv_seq++;
    return APP_OK;
}
