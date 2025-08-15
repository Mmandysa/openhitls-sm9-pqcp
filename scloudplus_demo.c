#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/crypt_eal_provider.h"
#include "crypto/crypt_eal_implprovider.h"
#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_eal_pkey.h"
#include "crypto/crypt_errno.h"
#include "bsl/bsl_err.h"             
#include "bsl/bsl_params.h" 
#include "pqcp/pqcp_err.h" 
#include "pqcp/pqcp_provider.h"
#include "pqcp/pqcp_types.h" 
#include "pqcp/pqcp_provider_impl.h"
#include "scloudplus/scloudplus_local.h"


int main(void)
{


    SCLOUDPLUS_Para para = {0};//参数存放

    //=======初始化=======
    int32_t ret = 0;
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    if (!libCtx) return -1;

    //随机数模块初始化（这里只支持sha系列和aes系列）
    ret=CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        printf("随机数初始化失败，错误码: %d\n", ret);
        return -1;
    }
    printf("随机数模块初始化成功\n");

    //scloudplus模块初始化
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ret=CRYPT_EAL_ProviderSetLoadPath(libCtx, "/usr/local/lib");
    if( ret != CRYPT_SUCCESS) {
        fprintf(stderr, "设置 PQCP 提供者加载路径失败: %d\n", ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return -1;
    }
    printf("PQCP 提供者加载路径设置成功\n");

    //检查路径确保pqcp_provider.so在/usr/local/lib下
    ret=CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, &mgrCtx);
    if( ret != CRYPT_SUCCESS) {
        fprintf(stderr, "加载 PQCP 提供者失败: %d\n", ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return -1;
    }
    printf("PQCP 提供者加载成功\n");

    // =======模拟RSU端生成密钥对并导出公钥给OBU端========
    // RSU初始化scloudplus上下文
    void *rsu_ctx = NULL;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id!= 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id== CRYPT_EAL_IMPLPKEYMGMT_NEWCTX) {
            // 调用创建上下文函数
            rsu_ctx = ((void*(*)(void*, int32_t))g_pqcpKeyMgmtScloudPlus[i].func)(NULL, CRYPT_PKEY_SCLOUDPLUS);
            break;
        }
    }
    if (rsu_ctx == NULL) {
        printf("[RSU]Failed to create SCLOUDPLUS context.\n");
        return -1;
    }
    printf("[RSU]SCLOUDPLUS context created.\n");
    // RSU生成密钥对
    //设置rsu安全等级
    uint32_t secBits = SCLOUDPLUS_SECBITS2;
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(rsu_ctx, 
                PQCP_SCLOUDPLUS_KEY_BITS, &secBits, sizeof(secBits));
            break;
        }
    }
    if (ret != PQCP_SUCCESS) {
        printf("[RSU]Failed to set security bits.\n");
        return -1;
    }
    printf("[RSU]Security bits set to %u.\n", secBits);
    //获取安全等级对应的参数
    
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        //int32_t PQCP_SCLOUDPLUS_Ctrl(SCLOUDPLUS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_CTRL) {
            ret = ((int32_t(*)(void*, int32_t, void*, uint32_t))g_pqcpKeyMgmtScloudPlus[i].func)(
                rsu_ctx, PQCP_SCLOUDPLUS_GET_PARA, &para, sizeof(para));
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
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GENKEY) {
            ret = ((int32_t(*)(void*))g_pqcpKeyMgmtScloudPlus[i].func)(rsu_ctx);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("[RSU] keygen failed"); return -1; }
    printf("[RSU]Key pair generated.\n");

    // RSU导出公钥
    uint8_t *rsu_pk = (uint8_t*)malloc(real_para->pkSize);
    uint8_t *rsu_sk = (uint8_t*)malloc(real_para->kemSkSize);
    BSL_Param rsu_getPrv = { .key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = rsu_sk, .valueLen = real_para->kemSkSize };
    BSL_Param rsu_getPub = { .key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = rsu_pk, .valueLen = real_para->pkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPRV) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(rsu_ctx, &rsu_getPrv);
        }
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_GETPUB) {
            ret |= ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(rsu_ctx, &rsu_getPub);
        }
    }
    if (ret != PQCP_SUCCESS) { puts("[RSU]Export keys failed"); return -1; }
    printf("[RSU]Export keys OK.\n");
    // printf("RSU公钥：\n");
    // for (int i = 0; i < real_para->pkSize; i++) {
    //     printf("%02x", rsu_pk[i]);
    // }
    // printf("\n");
    // printf("RSU私钥：\n");
    // for (int i = 0; i < real_para->kemSkSize; i++) {
    //     printf("%02x", rsu_sk[i]);
    // }
    // printf("\n");

    // =======模拟OBU端导入RSU端的公钥,并进行封装========
    // OBU初始化scloudplus上下文
    void *ctxE = NULL;
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
    // 设置rsu的公钥
    BSL_Param setPubE = { .key = CRYPT_PARAM_SCLOUDPLUS_PUBKEY, .value = rsu_pk, .valueLen =real_para->pkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPUB) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(ctxE, &setPubE);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxE set pub failed"); return -1; }
    uint8_t *ct=(uint8_t*)malloc(real_para->ctxSize) ;    // 密文
    uint8_t *k_shared_obu = (uint8_t*)malloc(real_para->ss);     // obu 端生成的共享密钥
    uint32_t  kLenobu = real_para->ss;
    uint32_t  ctLen = real_para->ctxSize;
    if (!ct) { printf("ct is NULL\n"); }
    if (!k_shared_obu) { printf("k_shared_obu is NULL\n"); }
    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE) {
            ret = ((int32_t(*)(void*,  uint8_t*, uint32_t*, uint8_t*, uint32_t*))
                g_pqcpKemScloudPlus[i].func)( ctxE,ct, &ctLen, k_shared_obu, &kLenobu);
            break;
        }
    }
    //int32_t PQCP_SCLOUDPLUS_Encaps(SCLOUDPLUS_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,uint32_t *ssLen)
    if (ret != PQCP_SUCCESS) {fprintf(stderr, "[obu]Encaps failed, ret = %d\n", ret);
        free(k_shared_obu);
        return -1;
    }
    printf("[obu]Encapsulation OK. ctLen=%u kLenobu=%u\n", ctLen, kLenobu);

    // =======模拟RSU端解封装========
    BSL_Param setPrvD = { .key = CRYPT_PARAM_SCLOUDPLUS_PRVKEY, .value = rsu_sk, .valueLen =real_para->kemSkSize };
    for (int i = 0; g_pqcpKeyMgmtScloudPlus[i].id != 0; i++) {
        if (g_pqcpKeyMgmtScloudPlus[i].id == CRYPT_EAL_IMPLPKEYMGMT_SETPRV) {
            ret = ((int32_t(*)(void*, BSL_Param*))g_pqcpKeyMgmtScloudPlus[i].func)(rsu_ctx, &setPrvD);
            break;
        }
    }
    if (ret != PQCP_SUCCESS) { puts("ctxD set prv failed"); return -1; }

    // === Decaps ===
    uint8_t *k_shared_rsu = (uint8_t*)malloc(real_para->ss);
    uint32_t kLenrsu = real_para->ss;

    for (int i = 0; g_pqcpKemScloudPlus[i].id != 0; i++) {
        if (g_pqcpKemScloudPlus[i].id == CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE) {
            ret = ((int32_t(*)(void*, const uint8_t*, uint32_t, uint8_t*, uint32_t*))g_pqcpKemScloudPlus[i].func)(
                rsu_ctx, ct, ctLen, k_shared_rsu, &kLenrsu);
            break;  
        }
    }
    if (ret!= PQCP_SUCCESS)
    {
        printf("Decapsulation failed, ret = %d\n", ret);
        free(k_shared_rsu);
        return -1;
    }
    printf("Decapsulation OK. kLenrsu=%u\n", kLenrsu);
    

    printf("k_shared_rsu:\n");
    for (int i = 0; i < kLenrsu; i++) {
        printf("%02x ", k_shared_rsu[i]);
    }
    printf("\n");
    printf("k_shared_obu:\n");
    for (int i = 0; i < kLenobu; i++) {
        printf("%02x ", k_shared_obu[i]);
    }
    printf("\n");

    if (kLenrsu != kLenobu || memcmp(k_shared_obu, k_shared_rsu, kLenrsu) != 0) {
        puts("k_shared mismatch!");
        return -1;
    }
    puts("Decaps OK. k_shared matches.");

    free(k_shared_rsu);
    free(k_shared_obu);
    free(ct);
    free(rsu_pk);
    free(rsu_sk);
    CRYPT_EAL_LibCtxFree(libCtx);
    return 0;
    


}