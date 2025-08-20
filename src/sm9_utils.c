#include "sm9_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <gmssl/sm9.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <openssl/rand.h>
#include "cjson/cJSON.h"
#define PASSWORD "obu_password"
#define MSKPATH "sm9_sign_master_key.pem"
#define MSPUBPATH "sm9_sign_master_public.pem"
#define USER_PRIPATH "sm9_user_sign_key.pem"

//主密钥生成，保存到sm9_sign_master_key.pem
//主公钥生成，保存到sm9_sign_master_public.pem
int sm9_master_init(void) {
    SM9_SIGN_MASTER_KEY master_key;
    // 生成主密钥（ks 和 Ppubs）
    if (sm9_sign_master_key_generate(&master_key) != 1) {
        printf("生成主密钥失败！\n");
        return -1;
        //主密钥保存在masterkey
    }

    // 将主密钥保存为 PEM 文件（加密存储）
    FILE *fp = fopen(MSKPATH, "wb");
    if (!fp) {
        printf("无法打开文件 %s\n", MSKPATH);
        return -1;
    }
    if (sm9_sign_master_key_info_encrypt_to_pem(&master_key, PASSWORD, fp) != 1) {
        printf("保存主密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 保存主公钥
    fp = fopen(MSPUBPATH, "wb");
    if (!fp) {
        printf("无法打开文件 %s\n", MSPUBPATH);
        return -1;
    }
    if (sm9_sign_master_public_key_to_pem(&master_key, fp) != 1) {
        printf("保存主公钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    printf("主密钥生成并保存为 %s\n", MSKPATH);
    printf("主公钥已生成并保存为 %s\n", MSPUBPATH);

    return APP_OK;
}

//用户私钥生成
int sm9_issue_prv_for_id(const char *id) {
    if (!id) return APP_ERR;

    SM9_SIGN_MASTER_KEY master_key;
    SM9_SIGN_KEY user_key;
    // 从 PEM 文件加载主密钥
    FILE *fp = fopen(MSKPATH, "rb");
    if (sm9_sign_master_key_info_decrypt_from_pem(&master_key, PASSWORD, fp) != 1) {
        printf("加载主密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 为用户生成签名密钥
    if (sm9_sign_master_key_extract_key(&master_key, id, strlen(id), &user_key) != 1) {
        printf("生成用户签名密钥失败！\n");
        return -1;
    }

    // 将用户密钥保存为 PEM 文件
    fp = fopen(USER_PRIPATH, "wb");
    if (sm9_sign_key_info_encrypt_to_pem(&user_key, PASSWORD, fp) != 1) {
        printf("保存用户密钥失败！\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    printf("用户签名密钥生成并保存为 %s\n", USER_PRIPATH);
    return APP_OK;
}

//加载SM9用户私钥
int load_sm9_sign_key(SM9_SIGN_KEY *key) {
    FILE *fp = fopen(USER_PRIPATH, "r");
    char *password = PASSWORD;
    if (!fp) { perror("打开SM9私钥文件失败"); return 0; }
    if (sm9_sign_key_info_decrypt_from_pem(key, password, fp) != 1) {
        fprintf(stderr, "加载SM9私钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

//加载SM9主公钥
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *mpk) {
    FILE *fp = fopen(MSPUBPATH, "r");
    if (!fp) { perror("打开SM9主公钥文件失败"); return 0; }
    if (sm9_sign_master_public_key_from_pem(mpk, fp) != 1) {
        fprintf(stderr, "加载SM9主公钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}


