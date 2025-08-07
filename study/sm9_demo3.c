# include <stdio.h>
# include <string.h>
# include <gmssl/sm9.h>
# include <gmssl/error.h>



int main() {
    SM9_SIGN_MASTER_KEY master_key;
    const char *master_password = "123456";
    const char *user_id = "京A12345"; // 用户ID
    const uint8_t message[] = "Hello, SM9!";
    uint8_t sig[SM9_SIGNATURE_SIZE];
    // 加载主公钥（验证方只需主公钥，无需主私钥）
    FILE *fp;
    fp = fopen("sm9_sign_master_public.pem", "rb");
    if (sm9_sign_master_public_key_from_pem(&master_key, fp) != 1) {
        printf("加载主公钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    fp=fopen("signature.bin","rb");
    fread(sig,1,SM9_SIGNATURE_SIZE,fp);
    fclose(fp);
    // 初始化验证上下文
    SM9_SIGN_CTX ctx;
    sm9_verify_init(&ctx);

    // 追加消息数据
    sm9_verify_update(&ctx, message, strlen((char *)message));

    // 验证签名
    int ret = sm9_verify_finish(&ctx, sig, SM9_SIGNATURE_SIZE, &master_key, user_id, strlen(user_id));
    if (ret == 1) {
        printf("签名验证成功！\n");
    } else if (ret == 0) {
        printf("签名验证失败！\n");
    } else {
        printf("验证过程出错！\n");
    }

    return 0;
}