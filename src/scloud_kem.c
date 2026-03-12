#include "scloud_kem.h"
#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/crypt_eal_provider.h"
#include "crypto/crypt_eal_implprovider.h"
#include "crypto/crypt_eal_pkey.h"
#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_errno.h"
#include "bsl/bsl_err.h"             
#include "bsl/bsl_params.h" 
#include "pqcp/pqcp_err.h" 
#include "pqcp/pqcp_provider.h"
#include "pqcp/pqcp_types.h" 

// 全局 libCtx / provMgr
static CRYPT_EAL_LibCtx *g_lib = NULL;
static CRYPT_EAL_ProvMgrCtx *g_mgr = NULL;

static int32_t secbits_to_alg_id(uint32_t secbits)
{
    switch (secbits) {
        case SCLOUDPLUS_SECBITS1:
            return PQCP_SCLOUDPLUS_128;
        case SCLOUDPLUS_SECBITS2:
            return PQCP_SCLOUDPLUS_192;
        case SCLOUDPLUS_SECBITS3:
            return PQCP_SCLOUDPLUS_256;
        default:
            return -1;
    }
}

/**
 * @brief 初始化 openHiTLS provider（PQCP）与随机数模块
 */
int scloud_global_init(const char *prov_path)
{
    int32_t ret;
    if (g_lib) return APP_OK;
    g_lib = CRYPT_EAL_LibCtxNew();
    if (!g_lib) return APP_ERR;

    ret = CRYPT_EAL_ProviderSetLoadPath(g_lib, prov_path);
    if (ret != CRYPT_SUCCESS) return APP_ERR;

    ret = CRYPT_EAL_ProviderLoad(g_lib, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, &g_mgr);
    if (ret != CRYPT_SUCCESS) return APP_ERR;

    ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) return APP_ERR;
    printf("[SCloudPlus] random number generator initialized\n");
    return APP_OK;
}

/**
 * @brief 释放全局 provider 与随机数资源（可选）
 */
void scloud_global_cleanup(void)
{
    if (g_lib) {
        (void)CRYPT_EAL_ProviderUnload(g_lib, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
        CRYPT_EAL_LibCtxFree(g_lib);
    }
    g_lib = NULL;
    g_mgr = NULL;
    CRYPT_EAL_RandDeinit();
}

/**
 * @brief 创建 SCloud+ pkey 上下文
 */
static CRYPT_EAL_PkeyCtx *new_pkey_ctx(void)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(g_lib, PQCP_PKEY_SCLOUDPLUS,
        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx != NULL) {
        printf("[SCloudPlus] new context created\n");
    }
    return ctx;
}

/**
 * @brief 设置 SCloud+ 参数集
 */
static int32_t set_para_by_secbits(CRYPT_EAL_PkeyCtx *ctx, uint32_t secbits)
{
    int32_t alg_id = secbits_to_alg_id(secbits);
    if (alg_id < 0) {
        return CRYPT_INVALID_ARG;
    }

    printf("[SCloudPlus] set parameter set for %u-bit security\n", secbits);
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &alg_id, sizeof(alg_id));
}

/**
 * @brief 查询长度类参数
 */
static int32_t get_pkey_u32(CRYPT_EAL_PkeyCtx *ctx, int32_t cmd, uint32_t *val)
{
    if (val == NULL) {
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_EAL_PkeyCtrl(ctx, cmd, val, sizeof(*val));
}

/**
 * @brief 从 provider 上下文导出公钥字节串
 */
static int32_t call_get_pub(CRYPT_EAL_PkeyCtx *ctx, uint8_t *out, uint32_t *outlen)
{
    BSL_Param p[] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, out, *outlen, 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyGetPubEx(ctx, p);
    if (ret == CRYPT_SUCCESS || ret == PQCP_SUCCESS) {
        *outlen = p[0].useLen;
    }
    return ret;
}

/**
 * @brief 从 provider 上下文导出私钥字节串
 */
static int32_t call_get_prv(CRYPT_EAL_PkeyCtx *ctx, uint8_t *out, uint32_t *outlen)
{
    BSL_Param p[] = {
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, out, *outlen, 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyGetPrvEx(ctx, p);
    if (ret == CRYPT_SUCCESS || ret == PQCP_SUCCESS) {
        *outlen = p[0].useLen;
    }
    return ret;
}

/**
 * @brief 释放 provider 创建的 pkey_ctx
 */
static void call_free_ctx(CRYPT_EAL_PkeyCtx *ctx)
{
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

/**
 * @brief 释放 SCloudCtx 内部资源
 */
void scloud_ctx_free(SCloudCtx *sc)
{
    if (!sc) return;
    if (sc->pkey_ctx) call_free_ctx(sc->pkey_ctx);
    sc->pkey_ctx = NULL;
    sc->pk_len = 0;
    sc->sk_len = 0;
}

/**
 * @brief Server 端生成一次性 SCloud+ KEM 密钥对（用于本次握手）
 */
int scloud_rsu_keygen(SCloudCtx *sc, uint32_t secbits, uint8_t *pub, uint32_t pub_cap, uint8_t *prv, uint32_t prv_cap)
{
    if (!sc || !pub || !prv) return APP_ERR;
    if (pub_cap == 0 || prv_cap == 0) return APP_ERR;

    /* 避免复用旧上下文：每次握手建议生成新的 keypair */
    scloud_ctx_free(sc);

    sc->pkey_ctx = new_pkey_ctx();
    if (!sc->pkey_ctx) return APP_ERR;

    int32_t ret = set_para_by_secbits(sc->pkey_ctx, secbits);
    if (ret != 0) return APP_ERR;

    if (CRYPT_EAL_PkeyGen(sc->pkey_ctx) != 0) return APP_ERR;
    printf("[SCloudPlus] key pair generated\n");

    uint32_t pub_need = 0;
    uint32_t prv_need = 0;
    if (get_pkey_u32(sc->pkey_ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pub_need) != 0) return APP_ERR;
    if (get_pkey_u32(sc->pkey_ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prv_need) != 0) return APP_ERR;
    if (pub_need > pub_cap || prv_need > prv_cap) return APP_ERR;

    uint32_t l1 = pub_cap;
    if (call_get_pub(sc->pkey_ctx, pub, &l1) != 0) return APP_ERR;
    sc->pk_len = l1;

    uint32_t l2 = prv_cap;
    if (call_get_prv(sc->pkey_ctx, prv, &l2) != 0) return APP_ERR;
    sc->sk_len = l2;

    printf("[SCloudPlus] Key generation complete. pk_len=%u sk_len=%u\n", sc->pk_len, sc->sk_len);
    return APP_OK;
}

/**
 * @brief 通过 provider 的 KEM 实现进行封装：输出 (ciphertext, shared_secret)
 */
static int32_t call_encaps(CRYPT_EAL_PkeyCtx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *ss, uint32_t *ssLen)
{
    return CRYPT_EAL_PkeyEncaps(ctx, ct, ctLen, ss, ssLen);
}

/**
 * @brief 通过 provider 的 KEM 实现进行解封：输入 ciphertext，输出 shared_secret
 */
static int32_t call_decaps(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *ct, uint32_t ctLen, uint8_t *ss, uint32_t *ssLen)
{
    return CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ss, ssLen);
}

/**
 * @brief 将对端公钥写入 provider 上下文（用于封装）
 */
static int32_t call_set_pub(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *pub, uint32_t pub_len)
{
    BSL_Param p[] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, (void *)pub, pub_len, 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeySetPubEx(ctx, p);
}

/**
 * @brief 将本端私钥写入 provider 上下文（用于解封）
 */
static int32_t call_set_prv(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *prv, uint32_t prv_len)
{
    BSL_Param p[] = {
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, (void *)prv, prv_len, 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeySetPrvEx(ctx, p);
}

/**
 * @brief Client 端：使用 Server 公钥做 KEM 封装，得到密文与共享秘密
 */
int scloud_obu_encaps(SCloudCtx *sc, uint32_t secbits, const uint8_t *rsu_pub, uint32_t rsu_pub_len,
                      uint8_t *cipher, uint32_t *cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len)
{
    if (!sc || !rsu_pub || rsu_pub_len == 0 || !cipher || !cipher_len || !k_pqc || !k_pqc_len) return APP_ERR;

    if (!sc->pkey_ctx) {
        sc->pkey_ctx = new_pkey_ctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }

    if (set_para_by_secbits(sc->pkey_ctx, secbits) != 0) return APP_ERR;
    if (call_set_pub(sc->pkey_ctx, rsu_pub, rsu_pub_len) != 0) return APP_ERR;
    if (CRYPT_EAL_PkeyEncapsInit(sc->pkey_ctx, NULL) != 0) return APP_ERR;

    /* 查询本算法密文长度，并检查调用者缓冲区容量 */
    uint32_t ct_need = 0;
    if (get_pkey_u32(sc->pkey_ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ct_need) != 0) return APP_ERR;
    if (ct_need > *cipher_len) return APP_ERR;

    uint32_t ct_cap = *cipher_len;
    *cipher_len = ct_cap;

    if (call_encaps(sc->pkey_ctx, cipher, cipher_len, k_pqc, k_pqc_len) != 0) return APP_ERR;
    if (*cipher_len != ct_need) {
        /* 保守处理：长度不一致视为失败，避免编码/解码分歧 */
        return APP_ERR;
    }
    return APP_OK;
}

/**
 * @brief Server 端：用私钥解封，得到共享秘密
 */
int scloud_rsu_decaps(SCloudCtx *sc, uint32_t secbits, const uint8_t *rsu_prv, uint32_t rsu_prv_len,
                      const uint8_t *cipher, uint32_t cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len)
{
    if (!sc || !rsu_prv || rsu_prv_len == 0 || !cipher || cipher_len == 0 || !k_pqc || !k_pqc_len) return APP_ERR;

    if (!sc->pkey_ctx) {
        sc->pkey_ctx = new_pkey_ctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }

    if (set_para_by_secbits(sc->pkey_ctx, secbits) != 0) return APP_ERR;
    if (call_set_prv(sc->pkey_ctx, rsu_prv, rsu_prv_len) != 0) return APP_ERR;
    if (CRYPT_EAL_PkeyDecapsInit(sc->pkey_ctx, NULL) != 0) return APP_ERR;

    if (call_decaps(sc->pkey_ctx, cipher, cipher_len, k_pqc, k_pqc_len) != 0) return APP_ERR;
    return APP_OK;
}
