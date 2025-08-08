#include <stdio.h>
#include <string.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

//主密钥生成和保存示例
int main() {
    SM9_SIGN_MASTER_KEY master_key;
    const char *master_password = "123456"; // 主密钥加密密码

    // 生成主密钥（ks 和 Ppubs）
    if (sm9_sign_master_key_generate(&master_key) != 1) {
        printf("生成主密钥失败！\n");
        return -1;
        //主密钥保存在masterkey
    }

    // 将主密钥保存为 PEM 文件（加密存储）
    FILE *fp = fopen("sm9_sign_master_key.pem", "wb");
    if (!fp) {
        printf("无法打开文件 sm9_sign_master_key.pem\n");
        return -1;
    }
    if (sm9_sign_master_key_info_encrypt_to_pem(&master_key, master_password, fp) != 1) {
        printf("保存主密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 保存主公钥
    fp = fopen("sm9_sign_master_public.pem", "wb");
    if (!fp) {
        printf("无法打开文件 sm9_sign_master_public.pem\n");
        return -1;
    }
    if (sm9_sign_master_public_key_to_pem(&master_key, fp) != 1) {
        printf("保存主公钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    printf("主密钥生成并保存成功！\n");
    printf("主公钥已生成并保存为 sm9_sign_master_public.pem\n");
    
    return 0;
}