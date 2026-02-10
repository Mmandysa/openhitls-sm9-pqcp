#ifndef SCLOUD_KEM_H
#define SCLOUD_KEM_H

#include <stdint.h>

/**
 * @file scloud_kem.h
 * @brief SCloud+（PQCP KEM）封装：用于 PQTLS 的抗量子密钥协商。
 *
 * 说明：
 * - 本模块只负责 KEM 的 keygen/encaps/decaps，不做“混合密钥”。
 * - 随机数与 provider 初始化通过 openHiTLS CRYPT_EAL_* 完成。
 */

#include "common.h"

typedef struct {
    void *pkey_ctx;   // SCloud+ pkey 上下文
    uint32_t pk_len;
    uint32_t sk_len;
    // 注意：真实长度由 Ctrl -> GET_PARA/GET_CIPHERLEN 等接口决定
} SCloudCtx;

/**
 * @brief 初始化 openHiTLS provider（PQCP）与随机数模块（进程内只需调用一次）
 */
int scloud_global_init(const char *prov_path);

/**
 * @brief 释放全局资源（可选，用于进程退出前清理）
 */
void scloud_global_cleanup(void);

/**
 * @brief 释放 SCloudCtx 内部的 pkey_ctx（建议每次握手结束后调用）
 */
void scloud_ctx_free(SCloudCtx *sc);

/**
 * @brief Server 端：创建 SCloud+ 上下文、设置安全等级、生成公私钥对
 */
int scloud_rsu_keygen(SCloudCtx *sc, uint32_t secbits, uint8_t *pub, uint32_t pub_cap, uint8_t *prv, uint32_t prv_cap);

/**
 * @brief Client 端：使用 Server 公钥做 KEM 封装，得到密文 C 与共享秘密 k_pqc
 */
int scloud_obu_encaps(SCloudCtx *sc, uint32_t secbits, const uint8_t *rsu_pub, uint32_t rsu_pub_len,
                      uint8_t *cipher, uint32_t *cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len);

/**
 * @brief Server 端：用私钥解封，得到共享秘密 k_pqc
 */
int scloud_rsu_decaps(SCloudCtx *sc, uint32_t secbits, const uint8_t *rsu_prv, uint32_t rsu_prv_len,
                      const uint8_t *cipher, uint32_t cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len);

#endif
