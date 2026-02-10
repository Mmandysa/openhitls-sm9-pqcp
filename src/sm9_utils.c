#include "sm9_utils.h"

#include "common.h"

#include <gmssl/pem.h>
#include <gmssl/error.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/**
 * @brief 确保 keys/ 目录存在（用于存放 SM9 pem 密钥文件）
 * @return APP_OK 成功；APP_ERR 失败
 */
static int ensure_keys_dir_exists(void)
{
    if (mkdir("keys", 0700) == 0) return APP_OK;
    if (errno == EEXIST) return APP_OK;
    perror("mkdir(keys)");
    return APP_ERR;
}

/**
 * @brief 生成 SM9 签名主密钥对（MSK/MPK），并写入 pem 文件
 */
int sm9_master_init(void)
{
    if (ensure_keys_dir_exists() != APP_OK) return APP_ERR;

    SM9_SIGN_MASTER_KEY master_key;
    if (sm9_sign_master_key_generate(&master_key) != 1) {
        error_print();
        return APP_ERR;
    }

    FILE *fp = fopen(SM9_SIGN_MSK_PATH, "wb");
    if (!fp) {
        perror("fopen(SM9_SIGN_MSK_PATH)");
        return APP_ERR;
    }
    if (sm9_sign_master_key_info_encrypt_to_pem(&master_key, SM9_KEY_PASSWORD, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);

    fp = fopen(SM9_SIGN_MPK_PATH, "wb");
    if (!fp) {
        perror("fopen(SM9_SIGN_MPK_PATH)");
        return APP_ERR;
    }
    if (sm9_sign_master_public_key_to_pem(&master_key, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);

    return APP_OK;
}

/**
 * @brief 为指定 ID 颁发 SM9 签名私钥，并写入 pem 文件
 */
int sm9_issue_prv_for_id(const char *id, const char *filepath)
{
    if (!id || id[0] == '\0' || !filepath || filepath[0] == '\0') return APP_ERR;
    if (ensure_keys_dir_exists() != APP_OK) return APP_ERR;

    SM9_SIGN_MASTER_KEY master_key;
    SM9_SIGN_KEY user_key;

    FILE *fp = fopen(SM9_SIGN_MSK_PATH, "rb");
    if (!fp) {
        perror("fopen(SM9_SIGN_MSK_PATH)");
        return APP_ERR;
    }
    if (sm9_sign_master_key_info_decrypt_from_pem(&master_key, SM9_KEY_PASSWORD, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);

    if (sm9_sign_master_key_extract_key(&master_key, id, strlen(id), &user_key) != 1) {
        error_print();
        return APP_ERR;
    }

    fp = fopen(filepath, "wb");
    if (!fp) {
        perror("fopen(user_sign_key)");
        return APP_ERR;
    }
    if (sm9_sign_key_info_encrypt_to_pem(&user_key, SM9_KEY_PASSWORD, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);

    return APP_OK;
}

/**
 * @brief 从文件加载 SM9 签名私钥（pem）
 */
int load_sm9_sign_key_from_file(SM9_SIGN_KEY *key, const char *filepath)
{
    if (!key || !filepath || filepath[0] == '\0') return APP_ERR;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        perror("fopen(sign_key)");
        return APP_ERR;
    }
    if (sm9_sign_key_info_decrypt_from_pem(key, SM9_KEY_PASSWORD, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);
    return APP_OK;
}

/**
 * @brief 从文件加载 SM9 签名主公钥（pem）
 */
int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *mpk)
{
    if (!mpk) return APP_ERR;

    FILE *fp = fopen(SM9_SIGN_MPK_PATH, "rb");
    if (!fp) {
        perror("fopen(SM9_SIGN_MPK_PATH)");
        return APP_ERR;
    }
    if (sm9_sign_master_public_key_from_pem(mpk, fp) != 1) {
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);
    return APP_OK;
}

/**
 * @brief SM9 对 msg 做签名，输出 signature
 */
int sign_message(const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len, const SM9_SIGN_KEY *user_key)
{
    if ((!msg && msg_len != 0) || !sig || !sig_len || !user_key) return APP_ERR;

    SM9_SIGN_CTX sign_ctx;
    if (sm9_sign_init(&sign_ctx) != 1) {
        error_print();
        return APP_ERR;
    }
    if (msg_len != 0) {
        if (sm9_sign_update(&sign_ctx, msg, msg_len) != 1) {
            error_print();
            return APP_ERR;
        }
    }
    if (sm9_sign_finish(&sign_ctx, (SM9_SIGN_KEY *)user_key, sig, sig_len) != 1) {
        error_print();
        return APP_ERR;
    }
    return APP_OK;
}

/**
 * @brief 验证签名：用 (MPK + user_id) 验证 signature
 */
int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *signature, size_t sig_len,
                     const SM9_SIGN_MASTER_KEY *mpk, const char *user_id)
{
    if ((!msg && msg_len != 0) || !signature || sig_len == 0 || !mpk || !user_id || user_id[0] == '\0') return APP_ERR;

    SM9_SIGN_CTX verify_ctx;
    if (sm9_verify_init(&verify_ctx) != 1) {
        error_print();
        return APP_ERR;
    }
    if (msg_len != 0) {
        if (sm9_verify_update(&verify_ctx, msg, msg_len) != 1) {
            error_print();
            return APP_ERR;
        }
    }
    if (sm9_verify_finish(&verify_ctx, signature, sig_len, (SM9_SIGN_MASTER_KEY *)mpk, user_id, strlen(user_id)) != 1) {
        error_print();
        return APP_ERR;
    }
    return APP_OK;
}

