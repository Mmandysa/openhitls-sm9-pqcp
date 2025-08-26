#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <gmssl/sm9.h>
#include <gmssl/sm2.h>

#define APP_OK              0
#define APP_ERR            -1

// 端口/缓冲区
#define DEFAULT_PORT        5555
#define MAX_PAYLOAD         40960
#define ID_MAX_LEN          64

// SCloud+ 安全等级
#ifndef SCLOUDPLUS_SECBITS1
#define SCLOUDPLUS_SECBITS1 128
#endif
#ifndef SCLOUDPLUS_SECBITS2
#define SCLOUDPLUS_SECBITS2 192
#endif
#ifndef SCLOUDPLUS_SECBITS3
#define SCLOUDPLUS_SECBITS3 256
#endif

// 协议消息类型
typedef enum {
    MSG_HELLO = 1,          // 客户端(OBU) -> 服务端(RSU)
    MSG_KEM_PUBKEY,         // RSU -> OBU (SCloud+ 公钥)
    MSG_KEM_CIPHERTEXT,     // OBU -> RSU (SCloud+ 密文)
    MSG_AUTH_SIGNATURE,     // 双方做 SM9 身份认证（OBU->RSU）
    MSG_AUTH_VERIFY_OK,     // RSU -> OBU
    MSG_DATA_SEC,           // 加密业务数据
    MSG_AUTH_REQUEST,       // OBU -> RSU (认证请求)
    MSG_AUTH_RESPONSE       // RSU -> OBU (认证响应)(挑战nonce)
} MsgType;

// 定长包头
#pragma pack(push, 1)
typedef struct {
    uint16_t type;      // MsgType
    uint32_t len;       // payload 长度
} PacketHeader;
#pragma pack(pop)

// 简单会话状态
typedef struct {
    uint8_t  k_pqc[16];       // 从 SCloud+ 派生的共享密钥（示例放够大）
    uint32_t k_pqc_len;

    uint8_t  k_final[32];     // 混合后的会话密钥（SM9||PQC 后 hash）
    uint32_t k_final_len;

    // 用于 SM9 签名认证：transcript 缓冲（握手数据拼接）
    uint8_t  transcript[40960];
    uint32_t transcript_len;

    // 用于存放 SM9 密钥交换的结果
    uint8_t k_sm9[32]; // 假设期望的密钥长度是32字节 (SM3哈希长度)
    uint32_t k_sm9_len;
    // 用于OBU在握手步骤之间临时保存 rA
    sm9_z256_t temp_rA;
} SessionKeys;

#endif // COMMON_H
