#ifndef PQTLS_CODEC_H
#define PQTLS_CODEC_H

#include <stdint.h>

/**
 * @file pqtls_codec.h
 * @brief PQTLS 的基础编码/解码工具：大小端、TLV、Handshake header。
 *
 * 设计目标：
 * - 不依赖“固定长度假设”，所有可变长字段必须带长度。
 * - 对任何输入都做边界检查，避免越界与整数溢出。
 */

typedef struct {
    uint8_t *data;
    uint32_t len;
    uint32_t cap;
} PQTLS_Buffer;

typedef struct {
    uint16_t t;
    uint16_t l;
    const uint8_t *v;
} PQTLS_Tlv;

/* =========================
 * Buffer 追加工具
 * ========================= */

/**
 * @brief 初始化一个 Buffer（使用调用者提供的存储空间）
 */
void pqtls_buf_init(PQTLS_Buffer *b, uint8_t *storage, uint32_t cap);

/**
 * @brief 向 Buffer 追加数据（带容量检查）
 * @return 0 成功；<0 失败
 */
int pqtls_buf_append(PQTLS_Buffer *b, const void *data, uint32_t len);

/**
 * @brief 向 Buffer 追加 1 字节
 */
int pqtls_buf_append_u8(PQTLS_Buffer *b, uint8_t v);

/**
 * @brief 向 Buffer 追加 uint16（网络字节序）
 */
int pqtls_buf_append_u16(PQTLS_Buffer *b, uint16_t v);

/**
 * @brief 向 Buffer 追加 uint24（网络字节序）
 */
int pqtls_buf_append_u24(PQTLS_Buffer *b, uint32_t v);

/**
 * @brief 向 Buffer 追加 uint32（网络字节序）
 */
int pqtls_buf_append_u32(PQTLS_Buffer *b, uint32_t v);

/**
 * @brief 向 Buffer 追加 uint64（网络字节序）
 */
int pqtls_buf_append_u64(PQTLS_Buffer *b, uint64_t v);

/* =========================
 * 大小端读写
 * ========================= */

uint16_t pqtls_read_u16(const uint8_t *p);
uint32_t pqtls_read_u24(const uint8_t *p);
uint32_t pqtls_read_u32(const uint8_t *p);
uint64_t pqtls_read_u64(const uint8_t *p);

void pqtls_write_u16(uint8_t *p, uint16_t v);
void pqtls_write_u24(uint8_t *p, uint32_t v);
void pqtls_write_u32(uint8_t *p, uint32_t v);
void pqtls_write_u64(uint8_t *p, uint64_t v);

/* =========================
 * TLV 编码/解码
 * ========================= */

/**
 * @brief 追加一个 TLV：t(2) + l(2) + v(l)
 */
int pqtls_tlv_append(PQTLS_Buffer *b, uint16_t t, const void *v, uint16_t l);

/**
 * @brief 追加 TLV(uint16 value)
 */
int pqtls_tlv_append_u16(PQTLS_Buffer *b, uint16_t t, uint16_t v);

/**
 * @brief 追加 TLV(uint8 value)
 */
int pqtls_tlv_append_u8(PQTLS_Buffer *b, uint16_t t, uint8_t v);

/**
 * @brief TLV 迭代解析：从 buf[off...] 读出一个 TLV
 * @return 0 成功；<0 失败（格式错误/越界）
 */
int pqtls_tlv_next(const uint8_t *buf, uint32_t buf_len, uint32_t *off, PQTLS_Tlv *out);

/* =========================
 * Handshake 消息编解码
 * ========================= */

/**
 * @brief 编码一条握手消息：hs_type(1) + hs_len(3) + body(hs_len)
 * @param out_len 输出实际长度（=4+body_len）
 */
int pqtls_hs_encode(uint8_t *out, uint32_t out_cap, uint8_t hs_type, const uint8_t *body, uint32_t body_len,
                    uint32_t *out_len);

/**
 * @brief 从 payload 中解析下一条握手消息，并返回 body 指针与长度
 *
 * @param payload   record payload
 * @param payload_len payload 长度
 * @param off       输入/输出：当前解析偏移量
 * @param hs_type   输出：握手类型
 * @param hs_body   输出：body 指针（指向 payload 内部）
 * @param hs_body_len 输出：body 长度
 * @param hs_bytes  输出：整条握手消息的起始指针（含 header）
 * @param hs_bytes_len 输出：整条握手消息长度（=4+hs_body_len）
 *
 * @return 0 成功；<0 失败
 */
int pqtls_hs_decode_next(const uint8_t *payload, uint32_t payload_len, uint32_t *off,
                         uint8_t *hs_type, const uint8_t **hs_body, uint32_t *hs_body_len,
                         const uint8_t **hs_bytes, uint32_t *hs_bytes_len);

#endif /* PQTLS_CODEC_H */

