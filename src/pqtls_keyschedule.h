#ifndef PQTLS_KEYSCHEDULE_H
#define PQTLS_KEYSCHEDULE_H

#include <stdint.h>

#include "pqtls_defs.h"

/**
 * @file pqtls_keyschedule.h
 * @brief PQTLS Key Schedule：SCloud+ 共享秘密 -> HKDF-SM3 派生 Finished/AppData 密钥。
 *
 * 说明：
 * - 本协议的“会话保密性/密钥交换”主要来自 SCloud+ KEM 输出的共享秘密 k_pqc。
 * - 派生过程遵循规划文档中的 HKDF-SM3（HMAC-SM3 作为 HKDF 的 MAC）。
 */

/**
 * @brief 派生 finished_key 与 record 层应用密钥/IV（双向）
 *
 * @param k_pqc        SCloud+ KEM 共享秘密
 * @param k_pqc_len    共享秘密长度
 * @param client_random 客户端随机数（32 bytes）
 * @param server_random 服务端随机数（32 bytes）
 * @param thash_key    transcript hash（用于 info 的绑定，32 bytes）
 *
 * @param out_finished_key_c2s  输出：client->server Finished key（32 bytes）
 * @param out_finished_key_s2c  输出：server->client Finished key（32 bytes）
 * @param out_app_key_c2s       输出：client->server record key（16 bytes）
 * @param out_app_iv_c2s        输出：client->server record iv（12 bytes）
 * @param out_app_key_s2c       输出：server->client record key（16 bytes）
 * @param out_app_iv_s2c        输出：server->client record iv（12 bytes）
 *
 * @return 0 成功；<0 失败
 */
int pqtls_derive_secrets(const uint8_t *k_pqc, uint32_t k_pqc_len,
                         const uint8_t client_random[PQTLS_RANDOM_LEN],
                         const uint8_t server_random[PQTLS_RANDOM_LEN],
                         const uint8_t thash_key[PQTLS_SM3_LEN],
                         uint8_t out_finished_key_c2s[PQTLS_SM3_LEN],
                         uint8_t out_finished_key_s2c[PQTLS_SM3_LEN],
                         uint8_t out_app_key_c2s[PQTLS_SM4_KEYLEN],
                         uint8_t out_app_iv_c2s[PQTLS_GCM_IVLEN],
                         uint8_t out_app_key_s2c[PQTLS_SM4_KEYLEN],
                         uint8_t out_app_iv_s2c[PQTLS_GCM_IVLEN]);

/**
 * @brief 计算 Finished.verify_data = HMAC-SM3(finished_key, thash)
 * @return 0 成功；<0 失败
 */
int pqtls_calc_finished_verify_data(const uint8_t finished_key[PQTLS_SM3_LEN],
                                    const uint8_t thash[PQTLS_SM3_LEN],
                                    uint8_t out_verify_data[PQTLS_SM3_LEN]);

#endif /* PQTLS_KEYSCHEDULE_H */

