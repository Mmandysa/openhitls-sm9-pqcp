#include <stdio.h>
#include <string.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


int main() {
    SM9_SIGN_MASTER_KEY master_key;
    const char *master_password = "123456";
    const char *user_id = "京A12345"; // 用户ID
    SM9_SIGN_KEY user_key;

    // 从 PEM 文件加载主密钥
    FILE *fp = fopen("sm9_sign_master_key.pem", "rb");
    if (sm9_sign_master_key_info_decrypt_from_pem(&master_key, master_password, fp) != 1) {
        printf("加载主密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 为用户生成签名密钥
    if (sm9_sign_master_key_extract_key(&master_key, user_id, strlen(user_id), &user_key) != 1) {
        printf("生成用户签名密钥失败！\n");
        return -1;
    }

    // 将用户密钥保存为 PEM 文件
    fp = fopen("sm9_user_sign_key.pem", "wb");
    if (sm9_sign_key_info_encrypt_to_pem(&user_key, "obu_password", fp) != 1) {
        printf("保存用户密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    printf("用户签名密钥生成并保存成功！\n");
    return 0;
}