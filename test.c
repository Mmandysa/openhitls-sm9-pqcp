#include "crypto/crypt_eal_md.h"
#include "crypto/crypt_algid.h"
#include <stdio.h>
#include <string.h>

void calculate_sha256() {
    const uint8_t data[] = "Hello, OpenHiTLS!";
    uint32_t data_len = strlen((const char*)data);
    
    // 1. 创建SHA-256上下文
    
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (!ctx) {
        printf("Failed to create MD context\n");
        return;
    }
    
    // 2. 初始化上下文
    if (CRYPT_EAL_MdInit(ctx) != 0) {
        printf("Failed to initialize MD context\n");
        CRYPT_EAL_MdFreeCtx(ctx);
        return;
    }
    
    // 3. 更新数据
    if (CRYPT_EAL_MdUpdate(ctx, data, data_len) != 0) {
        printf("Failed to update data\n");
        CRYPT_EAL_MdFreeCtx(ctx);
        return;
    }
    
    // 4. 获取哈希结果
    uint32_t digest_len = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA256);
    uint8_t digest[digest_len];
    
    if (CRYPT_EAL_MdFinal(ctx, digest, &digest_len) != 0) {
        printf("Failed to finalize digest\n");
    } else {
        printf("SHA-256 Digest: ");
        for (uint32_t i = 0; i < digest_len; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");
    }
    
    // 5. 释放上下文
    CRYPT_EAL_MdFreeCtx(ctx);
}
int main(void) {
    calculate_sha256();
    return 0;
}