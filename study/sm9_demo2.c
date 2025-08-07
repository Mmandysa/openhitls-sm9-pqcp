#include <stdio.h>
#include <string.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


int main() {
    SM9_SIGN_KEY user_key;
    const char *user_password = "user_password";
    const uint8_t message[] = "Hello, SM9!"; // 待签名的消息
    uint8_t sig[SM9_SIGNATURE_SIZE];         // 签名缓冲区
    size_t siglen;

    // 从 PEM 文件加载用户密钥
    FILE *fp;
    fp = fopen("sm9_user_sign_key.pem", "rb");
    if (sm9_sign_key_info_decrypt_from_pem(&user_key, user_password, fp) != 1) {
        printf("加载用户密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 初始化签名上下文
    SM9_SIGN_CTX ctx;
    sm9_sign_init(&ctx);

    // 追加消息数据（支持分块）
    sm9_sign_update(&ctx, message, strlen((char *)message));

    fp=fopen("signature.bin","wb");
    // 生成签名
    if (sm9_sign_finish(&ctx, &user_key, sig, &siglen) != 1) {
        printf("签名失败！\n");
        return -1;
    }

    printf("签名内容(hex): ");
    for (size_t i = 0; i < siglen; i++) {
        printf("%02X", sig[i]);
    }
    fwrite(sig,1,siglen,fp);
    fclose(fp);
    printf("\n");
    printf("签名生成成功！长度: %zu\n", siglen);

    return 0;
}