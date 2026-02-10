#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

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

// 定长包头（外层帧头）：type(2) + len(4)
#pragma pack(push, 1)
typedef struct {
    uint16_t type;      // RecordType（见 src/pqtls_defs.h）
    uint32_t len;       // payload 长度
} PacketHeader;
#pragma pack(pop)

#endif // COMMON_H
