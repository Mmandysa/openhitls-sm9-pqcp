#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm9.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <openssl/bn.h>

int main(void) {
    int ret = -1;
    SM9PublicParameters mpk;                // 公共参数（从 KGC 发布）
    SM9MasterSecret msk;                    // 主密钥（KGC）
    SM9_KEY_EXCHANGE_KEY user_key;          // 用户的身份私钥
    SM9_KEY_EXCHANGE_EPHEMERAL ephem;       // 临时参数 (rA, RA)
    uint8_t RA[512];                        // 导出的临时公钥
    size_t RAlen = sizeof(RA);

    const char *user_id = "Alice";

    // 1. 生成系统主密钥对 (KGC 操作)
    if (sm9_setup(SM9_TYPE_KEY_EXCHANGE, &mpk, &msk) != 1) {
        fprintf(stderr, "sm9_setup failed\n");
        goto end;
    }

    // 2. KGC 生成 Alice 的身份密钥 (dA)
    if (sm9_keygen(&mpk, &msk, user_id, strlen(user_id), &user_key) != 1) {
        fprintf(stderr, "sm9_keygen failed\n");
        goto end;
    }

    // 3. Alice 生成临时密钥对 (rA, RA)
    if (sm9_key_exchange_generate_ephemeral(&ephem, &mpk, NULL) != 1) {
        fprintf(stderr, "sm9_key_exchange_generate_ephemeral failed\n");
        goto end;
    }

    // 4. 导出临时公钥 RA = rA * P1
    if (sm9_key_exchange_export(&ephem, RA, &RAlen) != 1) {
        fprintf(stderr, "sm9_key_exchange_export failed\n");
        goto end;
    }

    // 5. 打印 RA
    printf("Alice 的临时公钥 RA (len=%zu):\n", RAlen);
    for (size_t i = 0; i < RAlen; i++) {
        printf("%02X", RA[i]);
    }
    printf("\n");

    ret = 0;

end:
    sm9_public_parameters_cleanup(&mpk);
    sm9_master_secret_cleanup(&msk);
    sm9_key_exchange_key_cleanup(&user_key);
    sm9_key_exchange_ephemeral_cleanup(&ephem);
    return ret;
}
