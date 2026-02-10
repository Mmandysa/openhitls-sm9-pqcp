#ifndef PQTLS_CRYPTO_H
#define PQTLS_CRYPTO_H

#include <stdint.h>

/**
 * @file pqtls_crypto.h
 * @brief PQTLS 使用的基础密码学工具封装（全部通过 openHiTLS CRYPT_EAL_* 调用）。
 *
 * 说明：
 * - 哈希：SM3
 * - MAC：HMAC-SM3
 * - KDF：HKDF-SM3（在此处用 RFC5869 的 HMAC 组合自行实现，底层仍用 openHiTLS 的 HMAC）
 */

/**
 * @brief 计算 SM3(data) -> out(32 bytes)
 * @return 0 成功；<0 失败
 */
int pqtls_sm3(const uint8_t *data, uint32_t len, uint8_t out[32]);

/**
 * @brief 计算 HMAC-SM3(key, data) -> out(32 bytes)
 * @return 0 成功；<0 失败
 */
int pqtls_hmac_sm3(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, uint8_t out[32]);

/**
 * @brief HKDF-Extract（SM3）：PRK = HMAC-SM3(salt, IKM)
 * @return 0 成功；<0 失败
 */
int pqtls_hkdf_extract_sm3(const uint8_t *salt, uint32_t salt_len, const uint8_t *ikm, uint32_t ikm_len,
                           uint8_t out_prk[32]);

/**
 * @brief HKDF-Expand（SM3）：OKM = HKDF-Expand(PRK, info, L)
 * @return 0 成功；<0 失败
 */
int pqtls_hkdf_expand_sm3(const uint8_t prk[32], const uint8_t *info, uint32_t info_len, uint8_t *okm,
                          uint32_t okm_len);

/**
 * @brief 常量时间比较（用于比较 tag/verify_data 等）
 * @return 0 相等；非0 不等
 */
int pqtls_ct_memcmp(const uint8_t *a, const uint8_t *b, uint32_t len);

/**
 * @brief 安全清理敏感数据（尽量避免被编译器优化掉）
 */
void pqtls_secure_clear(void *p, uint32_t len);

#endif /* PQTLS_CRYPTO_H */

