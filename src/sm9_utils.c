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
#include <gmssl/mem.h>
#include <gmssl/sm9_z256.h>
#define PASSWORD "obu_password"


int sm9_master_init(void) {
    SM9_SIGN_MASTER_KEY master_key;
    if (sm9_sign_master_key_generate(&master_key) != 1) return APP_ERR;
    FILE *fp = fopen(SIGN_MSK_PATH, "wb");
    if (!fp) return APP_ERR;
    if (sm9_sign_master_key_info_encrypt_to_pem(&master_key, PASSWORD, fp) != 1) {
        fclose(fp); return APP_ERR;
    }
    fclose(fp);
    fp = fopen(SIGN_MPK_PATH, "wb");
    if (!fp) return APP_ERR;
    if (sm9_sign_master_public_key_to_pem(&master_key, fp) != 1) {
        fclose(fp); return APP_ERR;
    }
    fclose(fp);
    printf("SIGN Master Keys generated: %s, %s\n", SIGN_MSK_PATH, SIGN_MPK_PATH);
    return APP_OK;
}

// *** 修改 *** 颁发签名私钥，写入到指定文件
int sm9_issue_prv_for_id(const char *id, const char *filepath) {
    if (!id || !filepath) return APP_ERR;
    SM9_SIGN_MASTER_KEY master_key;
    SM9_SIGN_KEY user_key;
    FILE *fp = fopen(SIGN_MSK_PATH, "rb");
    if (!fp) return APP_ERR;
    if (sm9_sign_master_key_info_decrypt_from_pem(&master_key, PASSWORD, fp) != 1) {
        fclose(fp); return APP_ERR;
    }
    fclose(fp);
    if (sm9_sign_master_key_extract_key(&master_key, id, strlen(id), &user_key) != 1) return APP_ERR;
    fp = fopen(filepath, "wb");
    if (!fp) return APP_ERR;
    if (sm9_sign_key_info_encrypt_to_pem(&user_key, PASSWORD, fp) != 1) {
        fclose(fp); return APP_ERR;
    }
    fclose(fp);
    printf("SIGN Private Key for ID '%s' saved to %s\n", id, filepath);
    return APP_OK;
}

// *** 修改 *** 加载OBU专属的签名私钥
int load_sm9_sign_key(SM9_SIGN_KEY *key) {
    FILE *fp = fopen(OBU_SIGN_KEY_PATH, "r");
    if (!fp) { perror("ERROR: Failed to open OBU's SIGN key file"); return 0; }
    if (sm9_sign_key_info_decrypt_from_pem(key, PASSWORD, fp) != 1) {
        fclose(fp); return 0;
    }
    fclose(fp);
    return 1;
}

int load_sm9_master_pub_key(SM9_SIGN_MASTER_KEY *mpk) {
    FILE *fp = fopen(SIGN_MPK_PATH, "r");
    if (!fp) { perror("ERROR: Failed to open SIGN master public key file"); return 0; }
    if (sm9_sign_master_public_key_from_pem(mpk, fp) != 1) {
        fclose(fp); return 0;
    }
    fclose(fp);
    return 1;
}


//签名
int sign_message(uint8_t *msg, size_t msg_len, uint8_t *sig, 
                size_t *sig_len, SM9_SIGN_KEY *user_key) {
    SM9_SIGN_CTX sign_ctx;
    if(sm9_sign_init(&sign_ctx)!=1)
    {
        printf("sm9_sign_init error\n");
        return APP_ERR;
    }
    if(sm9_sign_update(&sign_ctx, msg, msg_len)!=1)
    {
        printf("sm9_sign_update error\n");
        return APP_ERR;
    }
    if(sm9_sign_finish(&sign_ctx, user_key, sig, sig_len)!=1)
    {
        printf("sm9_sign_finish error\n");
        return APP_ERR;
    }
    return APP_OK;
}

//验证签名
int verify_signature(uint8_t *msg, size_t msg_len, uint8_t *signature, 
                        size_t sig_len, SM9_SIGN_MASTER_KEY *mpk, char *user_id) {
    SM9_SIGN_CTX verify_ctx;
    if(sm9_verify_init(&verify_ctx)!=1)
    {
        printf("sm9_verify_init error\n");
        return APP_ERR;
    }
    if(sm9_verify_update(&verify_ctx, msg, msg_len)!=1)
    {
        printf("sm9_verify_update error\n");
        return APP_ERR;
    }
    if(sm9_verify_finish(&verify_ctx, signature, sig_len,mpk, user_id, strlen(user_id))!=1)
    {
        printf("sm9_verify_finish error\n");
        return APP_ERR;
    }
    return APP_OK;
}

/**
 * @brief 初始化SM9加密/交换主密钥对 (Master Key Pair)
 *
 * @功能       生成一套全新的SM9加密主密钥(MSK)和主公钥(MPK)。
 *             主密钥用口令加密后存入 ENC_MSK_PATH 文件。
 *             主公钥直接存入 ENC_MPK_PATH 文件。
 *             此函数只需在系统部署时运行一次。
 * @return     成功返回 APP_OK，失败返回 APP_ERR。
 */
int sm9_enc_master_init(void) {
    SM9_ENC_MASTER_KEY master_key;

    // 1. 调用gmssl生成加密主密钥对
    if (sm9_enc_master_key_generate(&master_key) != 1) {
        fprintf(stderr, "ERROR: SM9 encryption master key generation failed!\n");
        error_print();
        return APP_ERR;
    }

    // 2. 将主密钥(MSK)加密后存入PEM文件
    FILE *fp = fopen(ENC_MSK_PATH, "wb");
    if (!fp) {
        perror("ERROR: Cannot open SM9 enc master key file for writing");
        return APP_ERR;
    }
    if (sm9_enc_master_key_info_encrypt_to_pem(&master_key, PASSWORD, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to save SM9 encryption master key!\n");
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);
    printf("SM9 Encryption Master Key generated and saved to %s\n", ENC_MSK_PATH);

    // 3. 将主公钥(MPK)存入PEM文件
    fp = fopen(ENC_MPK_PATH, "wb");
    if (!fp) {
        perror("ERROR: Cannot open SM9 enc master public key file for writing");
        return APP_ERR;
    }
    if (sm9_enc_master_public_key_to_pem(&master_key, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to save SM9 encryption master public key!\n");
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);
    printf("SM9 Encryption Master Public Key generated and saved to %s\n", ENC_MPK_PATH);

    return APP_OK;
}

int sm9_issue_enc_prv_for_id(const char *id, const char* filepath) {
    if (!id || strlen(id) == 0 || !filepath) {
        fprintf(stderr, "ERROR: Invalid ID or filepath for key generation.\n");
        return APP_ERR;
    }

    SM9_ENC_MASTER_KEY master_key;
    SM9_ENC_KEY user_key;

    FILE *fp = fopen(ENC_MSK_PATH, "rb");
    if (!fp) {
        perror("ERROR: Cannot open SM9 enc master key file for reading");
        return APP_ERR;
    }
    if (sm9_enc_master_key_info_decrypt_from_pem(&master_key, PASSWORD, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to load SM9 encryption master key!\n");
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);

    if (sm9_enc_master_key_extract_key(&master_key, id, strlen(id), &user_key) != 1) {
        fprintf(stderr, "ERROR: Failed to extract encryption key for ID '%s'!\n", id);
        error_print();
        return APP_ERR;
    }

    // *** 修改 *** 使用传入的文件路径
    fp = fopen(filepath, "wb");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open SM9 enc user key file for writing: %s\n", filepath);
        perror("");
        return APP_ERR;
    }
    if (sm9_enc_key_info_encrypt_to_pem(&user_key, PASSWORD, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to save SM9 encryption user key to %s!\n", filepath);
        error_print();
        fclose(fp);
        return APP_ERR;
    }
    fclose(fp);
    printf("SM9 Encryption Private Key for ID '%s' generated and saved to %s\n", id, filepath);

    return APP_OK;
}

// 加载自己的交换私钥
int load_sm9_enc_key(SM9_ENC_KEY *key,char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        perror("ERROR: Failed to open enc user key file");
        return 0;
    }
    if (sm9_enc_key_info_decrypt_from_pem(key, PASSWORD, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to load OBU's enc user key!\n");
        error_print();
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

/**
 * @brief 加载SM9加密/交换主公钥
 *
 * @功能       在程序运行时，从 ENC_MPK_PATH 文件中读取主公钥。
 * @param mpk  [输出] 一个指向 SM9_ENC_MASTER_KEY 结构体的指针，用于存放加载的公钥。
 *             (注意：gmssl中，加密主公钥结构体也用于存储，但只填充Ppube部分)
 * @return     成功返回1，失败返回0。
 */
int load_sm9_enc_master_pub_key(SM9_ENC_MASTER_KEY *mpk) {
    FILE *fp = fopen(ENC_MPK_PATH, "r");
    if (!fp) {
        perror("ERROR: Failed to open SM9 enc master public key file");
        return 0;
    }
    if (sm9_enc_master_public_key_from_pem(mpk, fp) != 1) {
        fprintf(stderr, "ERROR: Failed to load SM9 enc master public key!\n");
        error_print();
        fclose(fp);
        return 0;
    }
    fclose(fp);
    // +++ 新增打印 +++
    printf("--- [KEY LOAD DEBUG] ---\n");
    printf("Loaded ENC Master Public Key (Ppube): ");
    uint8_t mpk_buf[65];
    sm9_z256_point_to_uncompressed_octets(&mpk->Ppube, mpk_buf);
    for(int i=0; i<65; i++) printf("%02x", mpk_buf[i]);
    printf("\n---------------------------\n");
    return 1;
}

// 生成hello消息nonce||ID||signature
// 尝试增加RA
int generate_message_hello(uint8_t *msg, uint32_t *length, const char *sign_id,const char *exch_id,
                           SM9_SIGN_KEY *user_key, const SM9_Z256_POINT *RA) {
    uint8_t ra_buf[65]; // SM9点非压缩格式为65字节 (0x04 || x || y)
    size_t ra_len = sizeof(ra_buf);

    // 1. 将RA点对象 序列化为 字节串
    if (sm9_z256_point_to_uncompressed_octets(RA, ra_buf) != 1) {
        error_print();
        return APP_ERR;
    }

    // 2. 生成随机数 nonce
    uint8_t nonce[32];
    if (gen_nonce(nonce, 32) != APP_OK) {
        return APP_ERR;
    }
    
    // 3. 构造待签名的消息 M = nonce || RA || ID
    size_t offset = 0;
    memcpy(msg + offset, nonce, 32); offset += 32;
    memcpy(msg + offset, ra_buf, ra_len); offset += ra_len;
   
    // memcpy(msg + offset, user_id, strlen(user_id)); offset += strlen(user_id);
    // --- 修改为 ---
    memcpy(msg + offset, sign_id, strlen(sign_id)); offset += strlen(sign_id);
    memcpy(msg + offset, exch_id, strlen(exch_id)); offset += strlen(exch_id);
    size_t sign_data_len = offset;

    // 4. 对 M 进行签名
    uint8_t signature[128];
    size_t sig_len = sizeof(signature);
    if (sign_message(msg, sign_data_len, signature, &sig_len, user_key) != APP_OK) {
        printf("签名失败！\n");
        return APP_ERR;
    }

    // 5. 将签名附加到消息末尾，形成最终消息
    memcpy(msg + offset, signature, sig_len); offset += sig_len;
    *length = offset;

    printf("Generated Hello message with RA, total length: %u\n", *length);
    return APP_OK;
}


// 解析hello消息验证签名
// 带RA
int parse_message_hello(uint8_t *msg, size_t msg_len, char *sign_id, char *exch_id,
                        SM9_SIGN_MASTER_KEY *mpk, SM9_Z256_POINT *RA) {
    // 新消息格式: 32(nonce) + 65(RA) + 9(ID) + 104(sig) = 210 字节
    // 注意：这是一个脆弱的固定格式，仅用于演示。健壮的系统应使用TLV格式。
    if (msg_len != 219) {
        fprintf(stderr, "ERROR: Invalid hello message length, expected 210, got %zu\n", msg_len);
        return APP_ERR;
    }

    // 1. 根据固定偏移量解析消息
    size_t offset = 0;
    uint8_t *nonce = msg; offset += 32;
    uint8_t *ra_buf = msg + offset; offset += 65;
    size_t sign_id_len = 9; // 假设长度为9
    size_t exch_id_len = 9; // 假设长度为9
    memcpy(sign_id, msg + offset, sign_id_len); sign_id[sign_id_len] = '\0'; offset += sign_id_len;
    memcpy(exch_id, msg + offset, exch_id_len); exch_id[exch_id_len] = '\0'; offset += exch_id_len;
    uint8_t *signature = msg + offset;
    size_t sig_len = 104;

    size_t sign_data_len = 32 + 65 + sign_id_len + exch_id_len; // 签名的范围是 nonce || RA || ID

    // 2. 验证签名 (这是确保RA未被篡改的关键)
    if (verify_signature(msg, sign_data_len, signature, sig_len, mpk, sign_id) != APP_OK) {
        printf("签名验证失败！\n");
        return APP_ERR;
    }
    printf("Hello message signature verified successfully!\n");

    // 3. 验证通过后，将字节串 反序列化为 RA点对象
    if (sm9_z256_point_from_uncompressed_octets(RA, ra_buf) != 1) {
        error_print();
        return APP_ERR;
    }

    return APP_OK;
}

static int get_full_public_key_point(SM9_Z256_POINT *Q, const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen) {
    sm9_z256_t h;
    if (sm9_z256_hash1(h, id, idlen, SM9_HID_ENC) != 1) { // 注意: 标准规定用加密hid
        error_print();
        return -1;
    }
    sm9_z256_point_mul(Q, h, sm9_z256_generator());
    sm9_z256_point_add(Q, Q, &mpk->Ppube);
    return 1;
}

// OBU 发起函数
int sm9_kex_obu_start(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, const char *rsu_id, SM9_Z256_POINT *RA) {
    printf("[FINAL_KEX] OBU: Step 1 - Generating RA for RSU_ID=[%s]\n", rsu_id);
    SM9_Z256_POINT QB; // RSU的公钥点

    // 1. 获取RSU的完整公钥 QB
    if (get_full_public_key_point(&QB, mpk, rsu_id, strlen(rsu_id)) != 1) {
        fprintf(stderr, "ERROR: Failed to compute public point for RSU\n");
        return APP_ERR;
    }
    // 2. 生成随机数 rA 并保存
    if (sm9_z256_rand_range(ks->temp_rA, sm9_z256_order()) != 1) {
        error_print();
        return APP_ERR;
    }
    // 3. 计算 RA = rA * QB
    sm9_z256_point_mul(RA, ks->temp_rA, &QB);
    return APP_OK;
}

// RSU 响应并计算密钥
int sm9_kex_rsu_respond(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, SM9_ENC_KEY *key,
                        const char *obu_id, const char *rsu_id, const SM9_Z256_POINT *RA, SM9_Z256_POINT *RB) {
    printf("[FINAL_KEX] RSU: Step 2 - Responding and computing k_sm9 for OBU_ID=[%s]\n", obu_id);
    sm9_z256_t rB_local;
    SM9_Z256_POINT QA;
    sm9_z256_fp12_t shared_secret;
    uint8_t secret_bytes[32 * 12];
    uint8_t ra_bytes[65], rb_bytes[65];
    SM3_KDF_CTX kdf_ctx;

    // 1. 获取OBU的完整公钥 QA
    if (get_full_public_key_point(&QA, mpk, obu_id, strlen(obu_id)) != 1) return APP_ERR;

    // 2. 生成随机数 rB
    if (sm9_z256_rand_range(rB_local, sm9_z256_order()) != 1) return APP_ERR;

    // 3. 计算 RB = rB * QA
    sm9_z256_point_mul(RB, rB_local, &QA);

    // 4. 计算共享秘密: SK_B = e(RA, d_B) ^ rB
    sm9_z256_pairing(shared_secret, &key->de, RA);
    sm9_z256_fp12_pow(shared_secret, shared_secret, rB_local);
    
    // 打印
    sm9_z256_fp12_to_bytes(shared_secret, secret_bytes);
    printf("[DEBUG] RSU calculated Shared Secret (SK_B): ");
    for (int i = 0; i < 32; i++) printf("%02x", secret_bytes[i]);
    printf("\n");

    // 5. KDF
    ks->k_sm9_len = 32;
    sm9_z256_point_to_uncompressed_octets(RA, ra_bytes);
    sm9_z256_point_to_uncompressed_octets(RB, rb_bytes);
    sm3_kdf_init(&kdf_ctx, ks->k_sm9_len);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)obu_id, strlen(obu_id));
    sm3_kdf_update(&kdf_ctx, (uint8_t *)rsu_id, strlen(rsu_id));
    sm3_kdf_update(&kdf_ctx, ra_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, rb_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, secret_bytes, sizeof(secret_bytes));
    sm3_kdf_finish(&kdf_ctx, ks->k_sm9);
    
    gmssl_secure_clear(rB_local, sizeof(rB_local));
    printf("[DEBUG] RSU calculated k_sm9 (len=%u): ", ks->k_sm9_len);
    for (int i = 0; i < ks->k_sm9_len; i++) printf("%02x", ks->k_sm9[i]);
    printf("\n");
    return APP_OK;
}

// OBU 完成计算
int sm9_kex_obu_finish(SessionKeys *ks, SM9_ENC_MASTER_KEY *mpk, SM9_ENC_KEY *key,
                       const char *obu_id, const char *rsu_id, const SM9_Z256_POINT *RA, const SM9_Z256_POINT *RB) {
    printf("[FINAL_KEX] OBU: Step 3 - Finishing KEX and computing k_sm9\n");
    sm9_z256_fp12_t shared_secret;
    uint8_t secret_bytes[32 * 12];
    uint8_t ra_bytes[65], rb_bytes[65];
    SM3_KDF_CTX kdf_ctx;

    // 1. 计算共享秘密: SK_A = e(RB, d_A) ^ rA
    sm9_z256_pairing(shared_secret, &key->de, RB);
    sm9_z256_fp12_pow(shared_secret, shared_secret, ks->temp_rA);
    
    // 打印
    sm9_z256_fp12_to_bytes(shared_secret, secret_bytes);
    printf("[DEBUG] OBU calculated Shared Secret (SK_A): ");
    for (int i = 0; i < 32; i++) printf("%02x", secret_bytes[i]);
    printf("\n");
    
    // 2. KDF
    ks->k_sm9_len = 32;
    sm9_z256_point_to_uncompressed_octets(RA, ra_bytes);
    sm9_z256_point_to_uncompressed_octets(RB, rb_bytes);
    sm3_kdf_init(&kdf_ctx, ks->k_sm9_len);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)obu_id, strlen(obu_id));
    sm3_kdf_update(&kdf_ctx, (uint8_t *)rsu_id, strlen(rsu_id));
    sm3_kdf_update(&kdf_ctx, ra_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, rb_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, secret_bytes, sizeof(secret_bytes));
    sm3_kdf_finish(&kdf_ctx, ks->k_sm9);

    gmssl_secure_clear(ks->temp_rA, sizeof(ks->temp_rA));
    printf("[DEBUG] OBU calculated k_sm9 (len=%u): ", ks->k_sm9_len);
    for (int i = 0; i < ks->k_sm9_len; i++) printf("%02x", ks->k_sm9[i]);
    printf("\n");
    return APP_OK;
}

// OBU端：根据【正确】的密钥协商协议计算共享密钥
int correct_obu_compute_key(const SM9_ENC_MASTER_KEY *mpk, const SM9_ENC_KEY *key,
                            const char *rsu_id, size_t rsu_idlen, const sm9_z256_t rA,
                            const SM9_Z256_POINT *RB, uint8_t *sk, size_t klen,
                            const SM9_Z256_POINT* RA, const char* obu_id, size_t obu_idlen)
{
    SM9_Z256_POINT QB; // RSU的完整公钥
    sm9_z256_fp12_t term1, term2, shared_secret;
    uint8_t secret_bytes[32 * 12];
    uint8_t ra_bytes[65], rb_bytes[65];
    SM3_KDF_CTX kdf_ctx;

    // 1. 获取RSU的完整公钥 QB
    if (get_full_public_key_point(&QB, mpk, rsu_id, rsu_idlen) != 1) return -1;

    // 2. 计算共享秘密的第一部分: term1 = e(d_A, Q_B) ^ r_A
    sm9_z256_pairing(term1, &key->de, &QB);
    sm9_z256_fp12_pow(term1, term1, rA);

    // 3. 计算共享秘密的第二部分: term2 = e(Ppub_e, RB) ^ r_A
    sm9_z256_pairing(term2, sm9_z256_twist_generator(), &mpk->Ppube);
    // 注意：e(Ppub,RB) = e(ks*P1, rB*P1) 这是错的，应该是 e(Ppub_e, P2)
    // 正确公式是 e(deA, RB)
    sm9_z256_pairing(term2, &key->de, RB);
    sm9_z256_fp12_pow(term2, term2, rA);
    
    // 4. 最终共享秘密 = term1 * term2
    // 这个协议比想象的复杂，我们简化为一个已知正确的协议
    // Shared Secret = e(deA, RB) ^ rA
    sm9_z256_pairing(shared_secret, &key->de, RB);
    sm9_z256_fp12_pow(shared_secret, shared_secret, rA);

    // 打印共享秘密
    sm9_z256_fp12_to_bytes(shared_secret, secret_bytes);
    printf("[DEBUG] OBU calculated Shared Secret (SK_A): ");
    for (int i = 0; i < 32; i++) printf("%02x", secret_bytes[i]); // 只打印前32字节
    printf("\n");

    // 5. 使用 KDF 生成最终密钥
    sm9_z256_point_to_uncompressed_octets(RA, ra_bytes);
    sm9_z256_point_to_uncompressed_octets(RB, rb_bytes);

    sm3_kdf_init(&kdf_ctx, klen);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)obu_id, obu_idlen);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)rsu_id, rsu_idlen);
    sm3_kdf_update(&kdf_ctx, ra_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, rb_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, secret_bytes, sizeof(secret_bytes));
    sm3_kdf_finish(&kdf_ctx, sk);

    gmssl_secure_clear(&shared_secret, sizeof(shared_secret));
    return 1;
}

// RSU端：根据【正确】的密钥协商协议计算共享密钥
int correct_rsu_compute_key(const SM9_ENC_MASTER_KEY *mpk, const SM9_ENC_KEY *key,
                            const char *obu_id, size_t obu_idlen, const sm9_z256_t rB,
                            const SM9_Z256_POINT *RA, uint8_t *sk, size_t klen,
                            const SM9_Z256_POINT* RB, const char* rsu_id, size_t rsu_idlen)
{
    SM9_Z256_POINT QA; // OBU的完整公钥
    sm9_z256_fp12_t term1, term2, shared_secret;
    uint8_t secret_bytes[32 * 12];
    uint8_t ra_bytes[65], rb_bytes[65];
    SM3_KDF_CTX kdf_ctx;

    // 1. 获取OBU的完整公钥 QA
    if (get_full_public_key_point(&QA, mpk, obu_id, obu_idlen) != 1) return -1;
    
    // 2. 计算共享秘密
    // Shared Secret = e(deB, RA) ^ rB
    sm9_z256_pairing(shared_secret, &key->de, RA);
    sm9_z256_fp12_pow(shared_secret, shared_secret, rB);

    // 打印共享秘密
    sm9_z256_fp12_to_bytes(shared_secret, secret_bytes);
    printf("[DEBUG] RSU calculated Shared Secret (SK_B): ");
    for (int i = 0; i < 32; i++) printf("%02x", secret_bytes[i]); // 只打印前32字节
    printf("\n");

    // 3. 使用 KDF 生成最终密钥 (KDF输入必须和OBU端完全一样)
    sm9_z256_point_to_uncompressed_octets(RA, ra_bytes);
    sm9_z256_point_to_uncompressed_octets(RB, rb_bytes);

    sm3_kdf_init(&kdf_ctx, klen);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)obu_id, obu_idlen);
    sm3_kdf_update(&kdf_ctx, (uint8_t *)rsu_id, rsu_idlen);
    sm3_kdf_update(&kdf_ctx, ra_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, rb_bytes + 1, 64);
    sm3_kdf_update(&kdf_ctx, secret_bytes, sizeof(secret_bytes));
    sm3_kdf_finish(&kdf_ctx, sk);

    gmssl_secure_clear(&shared_secret, sizeof(shared_secret));
    return 1;
}
// 随机数生成
int gen_nonce(uint8_t *nonce, uint32_t len) {
    if (RAND_bytes(nonce, len) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return APP_ERR;
    }
    return APP_OK;
}