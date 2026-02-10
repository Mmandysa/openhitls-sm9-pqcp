#include "scloud_kem.h"
#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/crypt_eal_provider.h"
#include "crypto/crypt_eal_implprovider.h"
#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_errno.h"
#include "bsl/bsl_err.h"             
#include "bsl/bsl_params.h" 
#include "pqcp/pqcp_err.h" 
#include "pqcp/pqcp_provider.h"
#include "pqcp/pqcp_types.h" 
#include "pqcp/pqcp_provider_impl.h"
#include "scloudplus/scloudplus_local.h"

// 全局 libCtx / provMgr
static CRYPT_EAL_LibCtx *g_lib = NULL;
static CRYPT_EAL_ProvMgrCtx *g_mgr = NULL;

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
 * @brief 通过 provider 的实现函数表创建 SCloud+ pkey 上下文
 */
static void *find_and_call_newctx(void)
{
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            printf("[SCloudPlus] new context created\n");
            return ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
        }
    }
    return NULL;
}

/**
 * @brief 调用 provider 的 ctrl 接口（设置安全等级/查询密文长度等）
 */
static int32_t call_ctrl(void *ctx, int32_t cmd, void *val, uint32_t len)
{
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            if(cmd==PQCP_SCLOUDPLUS_KEY_BITS){
                printf("[SCloudPlus] PQCP_SCLOUDPLUS_KEY_BITS execute\n");
            }
            if(cmd==PQCP_SCLOUDPLUS_GET_PARA)
            {
                printf("[SCloudPlus] PQCP_SCLOUDPLUS_GET_PARA execute\n");
            }
            if(cmd==PQCP_SCLOUDPLUS_GET_CIPHERLEN)
            {
                printf("[SCloudPlus] PQCP_SCLOUDPLUS_GET_CIPHERLEN execute\n");
            }
            if(cmd==PQCP_SCLOUDPLUS_GET_SECBITS)
            {
                printf("[SCloudPlus] PQCP_SCLOUDPLUS_GET_SECBITS execute\n");
            }
            return ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(ctx, cmd, val, len);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 调用 provider 的 genkey 接口生成密钥对
 */
static int32_t call_gen(void *ctx)
{
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GENKEY) {
            printf("[SCloudPlus] key pair generated\n");
            return ((int32_t(*)(void *))g_pqcpKeyMgmtScloudPlus[i].func)(ctx);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 从 provider 上下文导出公钥字节串
 */
static int32_t call_get_pub(void *ctx, uint8_t *out, uint32_t *outlen)
{
    BSL_Param p = {0};
    p.key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY;
    p.value = out;
    p.valueLen = *outlen;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPUB) {
            int32_t r = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctx, &p);
            if (r == 0) *outlen = p.useLen;
            return r;
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 从 provider 上下文导出私钥字节串
 */
static int32_t call_get_prv(void *ctx, uint8_t *out, uint32_t *outlen)
{
    BSL_Param p = {0};
    p.key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY;
    p.value = out;
    p.valueLen = *outlen;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPRV) {
            int32_t r = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctx, &p);
            if (r == 0) *outlen = p.useLen;
            return r;
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 释放 provider 创建的 pkey_ctx
 */
static void call_free_ctx(void *ctx)
{
    if (!ctx) return;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_FREECTX) {
            ((void (*)(void *))g_pqcpKeyMgmtScloudPlus[i].func)(ctx);
            return;
        }
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

    sc->pkey_ctx = find_and_call_newctx();
    if (!sc->pkey_ctx) return APP_ERR;

    int32_t ret = call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secbits, sizeof(secbits));
    if (ret != 0) return APP_ERR;

    if (call_gen(sc->pkey_ctx) != 0) return APP_ERR;

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
static int32_t call_encaps(void *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *ss, uint32_t *ssLen)
{
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE) {
            return ((int32_t(*)(void*, uint8_t*, uint32_t*, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)
                   (ctx, ct, ctLen, ss, ssLen);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 通过 provider 的 KEM 实现进行解封：输入 ciphertext，输出 shared_secret
 */
static int32_t call_decaps(void *ctx, const uint8_t *ct, uint32_t ctLen, uint8_t *ss, uint32_t *ssLen)
{
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE) {
            return ((int32_t(*)(void*, const uint8_t*, uint32_t, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)
                   (ctx, ct, ctLen, ss, ssLen);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 将对端公钥写入 provider 上下文（用于封装）
 */
static int32_t call_set_pub(void *ctx, const uint8_t *pub, uint32_t pub_len)
{
    BSL_Param p = {.key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = (void *)pub, .valueLen = pub_len};
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPUB) {
            return ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctx, &p);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

/**
 * @brief 将本端私钥写入 provider 上下文（用于解封）
 */
static int32_t call_set_prv(void *ctx, const uint8_t *prv, uint32_t prv_len)
{
    BSL_Param p = {.key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = (void *)prv, .valueLen = prv_len};
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPRV) {
            return ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctx, &p);
        }
    }
    return CRYPT_NOT_SUPPORT;
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
        sc->pkey_ctx = find_and_call_newctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }

    if (call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secbits, sizeof(secbits)) != 0) return APP_ERR;
    if (call_set_pub(sc->pkey_ctx, rsu_pub, rsu_pub_len) != 0) return APP_ERR;

    /* 查询本算法密文长度，并检查调用者缓冲区容量 */
    uint32_t ct_need = 0;
    if (call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_GET_CIPHERLEN, &ct_need, sizeof(ct_need)) != 0) return APP_ERR;
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
        sc->pkey_ctx = find_and_call_newctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }

    if (call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secbits, sizeof(secbits)) != 0) return APP_ERR;
    if (call_set_prv(sc->pkey_ctx, rsu_prv, rsu_prv_len) != 0) return APP_ERR;

    if (call_decaps(sc->pkey_ctx, cipher, cipher_len, k_pqc, k_pqc_len) != 0) return APP_ERR;
    return APP_OK;
}
