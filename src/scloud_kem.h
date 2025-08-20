#ifndef SCLOUD_KEM_H
#define SCLOUD_KEM_H

#include <stdint.h>
#include "common.h"

typedef struct {
    void *pkey_ctx;   // SCloud+ pkey 上下文
    uint32_t pk_len;
    uint32_t sk_len;
    // 注意：真实长度由 Ctrl -> GET_PARA/GET_CIPHERLEN 等接口决定
} SCloudCtx;

// 初始化 openHiTLS & Provider（只需调用一次，可放 RSU 启动时） //测试通过
int scloud_global_init(const char *prov_path);

// RSU 端：创建 SCloud+ 上下文、设置安全等级、生成公私钥对
int scloud_rsu_keygen(SCloudCtx *sc, uint32_t secbits, uint8_t *pub, uint32_t pub_cap, uint8_t *prv, uint32_t prv_cap);

// OBU 端：使用 RSU 公钥做 KEM 封装，得到密文 C、共享密钥 k_pqc
int scloud_obu_encaps(SCloudCtx *sc, const uint8_t *rsu_pub, uint32_t rsu_pub_len,
                      uint8_t *cipher, uint32_t *cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len);

// RSU 端：用私钥解封，得到共享密钥 k_pqc
int scloud_rsu_decaps(SCloudCtx *sc, const uint8_t *rsu_prv, uint32_t rsu_prv_len,
                      const uint8_t *cipher, uint32_t cipher_len,
                      uint8_t *k_pqc, uint32_t *k_pqc_len);

// 混合密钥：H(k_sm9 || k_pqc) -> k_final（示例用 SM3）
int scloud_mix_keys_sm3(SessionKeys *ks);

#endif
