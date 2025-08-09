#include "crypt_eal_rand.h"
#include <stdio.h>
#include <stdint.h>

unsigned char nonce1[32];

int main() {

// 初始化随机数模块
    if (CRYPT_EAL_RandInit(CRYPT_RAND_SM4_CTR_DF, NULL, NULL, NULL, 0)) {
    fprintf(stderr, "[RSU] 随机数初始化失败\n");
    goto fail;
    }

    // 生成随机字节
    if (CRYPT_EAL_Randbytes(nonce1, sizeof(nonce1))) {
        fprintf(stderr, "[RSU] 生成 nonce1 失败\n");
    goto fail;
    }
    // 打印随机数
    printf("nonce1: ");
    for (int i = 0; i < sizeof(nonce1); i++) {
        printf("%02x", nonce1[i]);
    }
    printf("\n");

    // 退出
    return 0;

    // 错误处理
fail:
    return -1;
}
