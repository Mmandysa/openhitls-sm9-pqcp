#include "scloud_kem.h"
#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/crypt_eal_provider.h"
#include "crypto/crypt_eal_implprovider.h"
#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_eal_pkey.h"
#include "crypto/crypt_eal_md.h"
#include "crypto/crypt_errno.h"
#include "bsl/bsl_err.h"             
#include "bsl/bsl_params.h" 
#include "pqcp/pqcp_err.h" 
#include "pqcp/pqcp_provider.h"
#include "pqcp/pqcp_types.h" 
#include "pqcp/pqcp_provider_impl.h"
#include "scloudplus/scloudplus_local.h"
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

// 全局 libCtx / provMgr
static CRYPT_EAL_LibCtx *g_lib = NULL;
static CRYPT_EAL_ProvMgrCtx *g_mgr = NULL;

int scloud_global_init(const char *prov_path) {
    int32_t ret;
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

static void* find_and_call_newctx(void) {
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            printf("[SCloudPlus] new context created\n");
            return ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
        }
    }
    return NULL;
}

static int32_t call_ctrl(void *ctx, int32_t cmd, void *val, uint32_t len) {
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

static int32_t call_gen(void *ctx) {
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GENKEY) {
            printf("[SCloudPlus] key pair generated\n");
            return ((int32_t(*)(void *))g_pqcpKeyMgmtScloudPlus[i].func)(ctx);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

static int32_t call_get_pub(void *ctx, uint8_t *out, uint32_t *outlen) {
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

static int32_t call_get_prv(void *ctx, uint8_t *out, uint32_t *outlen) {
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

int scloud_rsu_keygen(SCloudCtx *sc, uint32_t secbits, uint8_t *pub, uint32_t pub_cap, uint8_t *prv, uint32_t prv_cap) {
    if (!sc || !pub || !prv) return APP_ERR;

    //创建上下文
    sc->pkey_ctx = find_and_call_newctx();
    if (!sc->pkey_ctx) return APP_ERR;

    //设置安全等级
    int32_t ret = call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secbits, sizeof(secbits));
    if (ret != 0) return APP_ERR;

    if (call_gen(sc->pkey_ctx) != 0) return APP_ERR;

    uint32_t l1 = pub_cap;
    if (call_get_pub(sc->pkey_ctx, pub, &l1) != 0) return APP_ERR;
    sc->pk_len = l1;

    uint32_t l2 = prv_cap;
    if (call_get_prv(sc->pkey_ctx, prv, &l2) != 0) return APP_ERR;
    sc->sk_len = l2;

    printf("[SCloudPlus] Key generation complete. Public key length: %u, Private key length: %u\n", sc->pk_len, sc->sk_len);
    //打印公钥（十六进制）
    // printf("Generated Public Key: \n");
    // for (uint32_t i = 0; i < sc->pk_len; i++) {
    //     printf("%02x", pub[i]);
    // }
    // printf("\n");

    // 打印私钥（十六进制）
    // printf("Generated Private Key: \n");
    // for (uint32_t i = 0; i < sc->sk_len; i++) {
    //     printf("%02X ", prv[i]);
    // }
    // printf("\n");


    return APP_OK;
}

// 封装：用 KEM 表
static int32_t call_encaps(void *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *ss, uint32_t *ssLen) {
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE) {
            return ((int32_t(*)(void*, uint8_t*, uint32_t*, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)
                   (ctx, ct, ctLen, ss, ssLen);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

// 解封
static int32_t call_decaps(void *ctx, const uint8_t *ct, uint32_t ctLen, uint8_t *ss, uint32_t *ssLen) {
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE) {
            return ((int32_t(*)(void*, const uint8_t*, uint32_t, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)
                   (ctx, ct, ctLen, ss, ssLen);
        }
    }
    return CRYPT_NOT_SUPPORT;
}

// OBU 设置 RSU 公钥然后封装
int scloud_obu_encaps(SCloudCtx *sc, const uint8_t *rsu_pub, uint32_t rsu_pub_len,
                      uint8_t *cipher, uint32_t *cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len)
{
    printf("rsu_pub_len: %u\n", rsu_pub_len);
    if (!sc || !cipher || !cipher_len || !k_pqc || !k_pqc_len || !rsu_pub) {
        printf("[SCloudPlus] Invalid parameters\n");
        return APP_ERR;
    }
    if (!sc->pkey_ctx) {
        sc->pkey_ctx = find_and_call_newctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }
    // 设置加密等级
    uint32_t secBits = SCLOUDPLUS_SECBITS1;
    int32_t ret = call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
    if (ret != 0) {
        printf("[SCloudPlus] Set security level failed\n");
        return APP_ERR;
    }
    // set pub
    BSL_Param setPub = {.key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = rsu_pub, .valueLen = rsu_pub_len};

    for (int i=0; g_pqcpKeyMgmtScloudPlus[i].id!=0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPUB) {
            if (((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(sc->pkey_ctx, &setPub) != 0)     
            {printf("[SCloudPlus] Set public key failed\n");return APP_ERR;}
            break;
        }
    }

    // 获取密文长度（ctrl）
    uint32_t ct_len_tmp = 0;
    if (call_ctrl(sc->pkey_ctx, PQCP_SCLOUDPLUS_GET_CIPHERLEN, &ct_len_tmp, sizeof(ct_len_tmp)) != 0) return APP_ERR;
    *cipher_len = ct_len_tmp;

    // 封装
    if (call_encaps(sc->pkey_ctx, cipher, cipher_len, k_pqc, k_pqc_len) != 0) return APP_ERR;
    printf("[SCloudPlus] Encapsulation complete. Cipher length: %u, Shared secret length: %u\n", *cipher_len, *k_pqc_len);
    return APP_OK;
}

int scloud_rsu_decaps(SCloudCtx *sc, const uint8_t *rsu_prv, uint32_t rsu_prv_len,
                      const uint8_t *cipher, uint32_t cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len)
{
    if (!sc || !rsu_prv || !cipher || !k_pqc || !k_pqc_len) return APP_ERR;
    if (!sc->pkey_ctx) {
        sc->pkey_ctx = find_and_call_newctx();
        if (!sc->pkey_ctx) return APP_ERR;
    }
    // set prv
    BSL_Param setPrv = {0};
    setPrv.key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY;
    setPrv.value = (void*)rsu_prv;
    setPrv.valueLen = rsu_prv_len;

    for (int i=0; g_pqcpKeyMgmtScloudPlus[i].id!=0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPRV) {
            if (((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(sc->pkey_ctx, &setPrv) != 0)
                return APP_ERR;
            break;
        }
    }

    if (call_decaps(sc->pkey_ctx, cipher, cipher_len, k_pqc, k_pqc_len) != 0) return APP_ERR;
    return APP_OK;
}

int scloud_mix_keys_sm3(SessionKeys *ks)
{
    unsigned char *kdf_in = malloc(ks->transcript_len + 64);
    if (!kdf_in) { fprintf(stderr, "malloc fail\n"); return -1; }
    size_t off = 0;
    memcpy(kdf_in + off, ks->k_pqc, 64); off += 64;
    memcpy(kdf_in + off, ks->transcript, ks->transcript_len); off += ks->transcript_len;

    unsigned char dgst[SM3_DIGEST_SIZE];
    SM3_CTX sm3ctx;
    sm3_init(&sm3ctx);
    sm3_update(&sm3ctx, kdf_in, off);
    sm3_finish(&sm3ctx, dgst);

    free(kdf_in);

    memcpy(ks->k_final, dgst, 64);
    for (int i = 0; i < 64; i++) {
        printf("%02x", ks->k_final[i]);
    }
    ks->k_final_len = 64;
    printf("\n");
}
