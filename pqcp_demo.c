#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "crypto/crypt_eal_provider.h"
#include "crypto/crypt_eal_implprovider.h"
#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_eal_pkey.h"
#include "crypto/crypt_errno.h"      // 通用 PKEY API
#include "bsl/bsl_err.h"             
#include "bsl/bsl_params.h" 
#include "pqcp/pqcp_err.h" 
#include "pqcp/pqcp_provider.h"
#include "pqcp/pqcp_types.h" 
#include "pqcp/pqcp_provider_impl.h"
#include "scloudplus/scloudplus_local.h"



int main(void) {
    int32_t ret;

    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);//随机数模块初始化


    if (!libCtx) return -1;
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ret=CRYPT_EAL_ProviderSetLoadPath(libCtx, "/usr/local/lib");
    if( ret != CRYPT_SUCCESS) {
        fprintf(stderr, "设置 PQCP 提供者加载路径失败: %d\n", ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return -1;
    }

    //检查路径确保pqcp_provider.so在/usr/local/lib下
    ret=CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, &mgrCtx);
    if( ret != CRYPT_SUCCESS) {
        fprintf(stderr, "加载 PQCP 提供者失败: %d\n", ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return -1;
    }

    // A初始化scloudplus上下文
    void *pkey_ctx = NULL;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id!= 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id== CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            // 调用创建上下文函数
            pkey_ctx = ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
            break;
        }
    }
    if (pkey_ctx == NULL) {
        printf("Failed to create SCLOUDPLUS context.\n");
        return -1;
    }
    printf("SCLOUDPLUS context created.\n");

    
    //A设置安全等级
    uint32_t secBits = SCLOUDPLUS_SECBITS2;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(pkey_ctx, 
                PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
            break;
        }
    }
    if (ret != PQCP_SUCCESS) {
        printf("Failed to set security bits.\n");
        return -1;
    }
    printf("Security bits set to %u.\n", secBits);

    // A取得参数（尺寸）
    SCLOUDPLUS_Para para = {0};
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        //int32_t PQCP_SCLOUDPLUS_Ctrl(SCLOUDPLUS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(
                pkey_ctx, PQCP_SCLOUDPLUS_GET_PARA, &para, sizeof(para));
            break;
        }
    }
    uintptr_t para_ptr_value = 0;
    if (ret != PQCP_SUCCESS) {
        printf("GET_PARA failed: %d\n", ret);
        return -1;
    }
    memcpy(&para_ptr_value, &para, sizeof(uintptr_t));
    SCLOUDPLUS_Para *real_para = (SCLOUDPLUS_Para *)para_ptr_value;
    printf("解析出的参数：\n"
       "  pkSize=%u\n  kemSkSize=%u\n  ctxSize=%u\n  ss=%u\n",
       real_para->pkSize, real_para->kemSkSize, real_para->ctxSize, real_para->ss);
    //printf("[para] pkSize=%u kemSkSize=%u ctxSize=%u ss=%u\n",para.pkSize, para.kemSkSize, para.ctxSize, para.ss);

    // A生成密钥对
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id!= 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GENKEY) {
            ret = ((int32_t(*)(void *))g_pqcpKeyMgmtScloudPlus[i].func)(pkey_ctx);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) {
        printf("Key generation failed.\n");
        return -1;
    }
    printf("Key pair generated.\n");

    // === 导出 A 端（OBU）的密钥对 ===
    uint8_t *A_pk  = (uint8_t*)malloc(para.pkSize);
    uint8_t *A_sk  = (uint8_t*)malloc(para.kemSkSize);
    if (!A_pk || !A_sk) return -1;

    BSL_Param getPrv = { .key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = A_sk, .valueLen = para.kemSkSize };
    BSL_Param getPub = { .key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = A_pk, .valueLen = para.pkSize };

    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPRV) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(pkey_ctx, &getPrv);
        }
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPUB) {
            ret |= ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(pkey_ctx, &getPub);
        }
    }
    if (ret != PQCP_SUCCESS) {
        printf("Export A keys failed.\n");
        return -1;
    }
    printf("Export A keys OK. useLen sk=%u pk=%u\n", getPrv.useLen, getPub.useLen);


    
    // === 导出 B 端的公钥 ===
    // === 创建 B 端（RSU）上下文并生成 ===
    void *B_ctx = NULL;

    // NEWCTX
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            B_ctx = ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
            break;
        }
    }
    if (!B_ctx) { puts("Create B_ctx failed"); return -1; }

    // CTRL 设置同样的安全等级
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(
                B_ctx, PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("B set bits failed"); return -1; }

    // 生成 B 端密钥对
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GENKEY) {
            ret = ((int32_t(*)(void*))g_pqcpKeyMgmtScloudPlus[i].func)(B_ctx);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("B keygen failed"); return -1; }

    // 导出 B 的密钥（至少要导出 pk 给 A 用于封装）
    uint8_t *B_pk = (uint8_t*)malloc(para.pkSize);
    uint8_t *B_sk = (uint8_t*)malloc(para.kemSkSize);
    BSL_Param BgetPrv = { .key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = B_sk, .valueLen = para.kemSkSize };
    BSL_Param BgetPub = { .key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = B_pk, .valueLen = para.pkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPRV) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(B_ctx, &BgetPrv);
        }
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPUB) {
            ret |= ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(B_ctx, &BgetPub);
        }
    }
    if (ret != PQCP_SUCCESS) { puts("Export B keys failed"); return -1; }
    printf("Export B keys OK.\n");

    // === A 端封装（Encapsulation）===
    // 分配密文和共享密钥缓冲区
    // === 构造一个仅用于 Encaps 的 ctxE，并设置 B 的公钥 ===

    
    void *ctxE = NULL;
    // NEWCTX
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            ctxE = ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
            break;
        }
    }
    if (!ctxE) { puts("Create ctxE failed"); return -1; }
    // 设安全等级
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(
                ctxE, PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxE set bits failed"); return -1; }
    // 设置 B 的公钥
    BSL_Param setPubE = { .key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = B_pk, .valueLen = para.pkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPUB) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctxE, &setPubE);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxE set pub failed"); return -1; }
    uint8_t *ct=(uint8_t*)malloc(real_para->ctxSize) ;    // 密文
    uint8_t *k_pqc_A = (uint8_t*)malloc(para.ss);     // A 端生成的共享密钥
    uint32_t  kLenA = para.ss;
    uint32_t  ctLen = real_para->ctxSize;
    printf("ctxsize=%u ctsize=%u\n", real_para->ctxSize, ctLen);
    if (!ct) { printf("ct is NULL\n"); }
    if (!k_pqc_A) { printf("k_pqc_A is NULL\n"); }
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE) {
            ret = ((int32_t(*)(void*,  uint8_t*, uint32_t*, uint8_t*, uint32_t*))
                g_pqcpKemScloudPlus[i].func)(pkey_ctx, ct, &ctLen, k_pqc_A, &kLenA);
            break;
        }
    }
    //int32_t PQCP_SCLOUDPLUS_Encaps(SCLOUDPLUS_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,uint32_t *ssLen)
    if (ret != PQCP_SUCCESS) {fprintf(stderr, "Encaps failed, ret = %d\n", ret);
        free(k_pqc_A);
        return -1;
    }
    printf("Encapsulation OK. ctLen=%u kLenA=%u\n", ctLen, kLenA);


    // === 构造 Decaps 上下文，设置 B 的私钥 ===
    void *ctxD = NULL;
    // NEWCTX
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            ctxD = ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
            break;
        }
    }
    if (!ctxD) { puts("Create ctxD failed"); return -1; }
    // 设安全等级
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(
                ctxD, PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxD set bits failed"); return -1; }

    // 设置 B 的私钥
    BSL_Param setPrvD = { .key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = B_sk, .valueLen = para.kemSkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPRV) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctxD, &setPrvD);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxD set prv failed"); return -1; }

    // === Decaps ===
    uint8_t *k_pqc_B = (uint8_t*)malloc(para.ss);
    uint32_t kLenB = para.ss;

    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE) {
            ret = ((int32_t(*)(void*, const uint8_t*, uint32_t, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)(
                ctxD, ct, ctLen, k_pqc_B, &kLenB);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("Decaps failed"); return -1; }
    printf("Decapsulation OK. kLenB=%u\n", kLenB);
    printf("k_pqc_A:\n");
    for (int i = 0; i < kLenA; i++) {
        printf("%02x ", k_pqc_A[i]);
    }
    printf("\n");
    printf("k_pqc_B:\n");
    for (int i = 0; i < kLenB; i++) {
        printf("%02x ", k_pqc_B[i]);
    }
    printf("\n");

    if (kLenA != kLenB || memcmp(k_pqc_A, k_pqc_B, kLenA) != 0) {
        puts("k_pqc mismatch!");
        return -1;
    }
    puts("Decaps OK. k_pqc matches.");

    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_RandDeinit();

    printf("success\n");
    return 0;
}
