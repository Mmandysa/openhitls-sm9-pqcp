#include "pqtls_codec.h"

#include <string.h>

/* =========================
 * Buffer
 * ========================= */

/**
 * @brief 初始化 Buffer（使用调用者提供的存储空间）
 */
void pqtls_buf_init(PQTLS_Buffer *b, uint8_t *storage, uint32_t cap)
{
    if (!b) return;
    b->data = storage;
    b->len = 0;
    b->cap = cap;
}

/**
 * @brief 向 Buffer 追加一段数据（带容量检查）
 */
int pqtls_buf_append(PQTLS_Buffer *b, const void *data, uint32_t len)
{
    if (!b || (!data && len != 0)) return -1;
    if (len > (b->cap - b->len)) return -1;
    if (len != 0) {
        memcpy(b->data + b->len, data, len);
        b->len += len;
    }
    return 0;
}

/**
 * @brief 向 Buffer 追加 1 字节
 */
int pqtls_buf_append_u8(PQTLS_Buffer *b, uint8_t v)
{
    return pqtls_buf_append(b, &v, 1);
}

/**
 * @brief 向 Buffer 追加 uint16（网络字节序）
 */
int pqtls_buf_append_u16(PQTLS_Buffer *b, uint16_t v)
{
    uint8_t tmp[2];
    pqtls_write_u16(tmp, v);
    return pqtls_buf_append(b, tmp, sizeof(tmp));
}

/**
 * @brief 向 Buffer 追加 uint24（网络字节序）
 */
int pqtls_buf_append_u24(PQTLS_Buffer *b, uint32_t v)
{
    if (v > 0xFFFFFFu) return -1;
    uint8_t tmp[3];
    pqtls_write_u24(tmp, v);
    return pqtls_buf_append(b, tmp, sizeof(tmp));
}

/**
 * @brief 向 Buffer 追加 uint32（网络字节序）
 */
int pqtls_buf_append_u32(PQTLS_Buffer *b, uint32_t v)
{
    uint8_t tmp[4];
    pqtls_write_u32(tmp, v);
    return pqtls_buf_append(b, tmp, sizeof(tmp));
}

/**
 * @brief 向 Buffer 追加 uint64（网络字节序）
 */
int pqtls_buf_append_u64(PQTLS_Buffer *b, uint64_t v)
{
    uint8_t tmp[8];
    pqtls_write_u64(tmp, v);
    return pqtls_buf_append(b, tmp, sizeof(tmp));
}

/* =========================
 * Big-endian read/write
 * ========================= */

/**
 * @brief 读取网络字节序 uint16
 */
uint16_t pqtls_read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/**
 * @brief 读取网络字节序 uint24
 */
uint32_t pqtls_read_u24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/**
 * @brief 读取网络字节序 uint32
 */
uint32_t pqtls_read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief 读取网络字节序 uint64
 */
uint64_t pqtls_read_u64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/**
 * @brief 写入网络字节序 uint16
 */
void pqtls_write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

/**
 * @brief 写入网络字节序 uint24
 */
void pqtls_write_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 16) & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)(v & 0xFFu);
}

/**
 * @brief 写入网络字节序 uint32
 */
void pqtls_write_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >> 8) & 0xFFu);
    p[3] = (uint8_t)(v & 0xFFu);
}

/**
 * @brief 写入网络字节序 uint64
 */
void pqtls_write_u64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)((v >> 48) & 0xFFu);
    p[2] = (uint8_t)((v >> 40) & 0xFFu);
    p[3] = (uint8_t)((v >> 32) & 0xFFu);
    p[4] = (uint8_t)((v >> 24) & 0xFFu);
    p[5] = (uint8_t)((v >> 16) & 0xFFu);
    p[6] = (uint8_t)((v >> 8) & 0xFFu);
    p[7] = (uint8_t)(v & 0xFFu);
}

/* =========================
 * TLV
 * ========================= */

int pqtls_tlv_append(PQTLS_Buffer *b, uint16_t t, const void *v, uint16_t l)
{
    if (!b) return -1;
    if (pqtls_buf_append_u16(b, t) != 0) return -1;
    if (pqtls_buf_append_u16(b, l) != 0) return -1;
    if (l != 0 && v != NULL) {
        if (pqtls_buf_append(b, v, l) != 0) return -1;
    } else if (l != 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief 追加 TLV：value 为 uint16（网络字节序）
 */
int pqtls_tlv_append_u16(PQTLS_Buffer *b, uint16_t t, uint16_t v)
{
    uint8_t tmp[2];
    pqtls_write_u16(tmp, v);
    return pqtls_tlv_append(b, t, tmp, (uint16_t)sizeof(tmp));
}

/**
 * @brief 追加 TLV：value 为 uint8
 */
int pqtls_tlv_append_u8(PQTLS_Buffer *b, uint16_t t, uint8_t v)
{
    return pqtls_tlv_append(b, t, &v, 1);
}

/**
 * @brief 从 buf[off...] 解析下一条 TLV（越界/格式错误返回失败）
 */
int pqtls_tlv_next(const uint8_t *buf, uint32_t buf_len, uint32_t *off, PQTLS_Tlv *out)
{
    if (!buf || !off || !out) return -1;
    if (*off > buf_len) return -1;
    if (buf_len - *off < 4) return -1;
    uint16_t t = pqtls_read_u16(buf + *off);
    uint16_t l = pqtls_read_u16(buf + *off + 2);
    *off += 4;
    if ((uint32_t)l > (buf_len - *off)) return -1;

    out->t = t;
    out->l = l;
    out->v = buf + *off;
    *off += l;
    return 0;
}

/* =========================
 * Handshake msg
 * ========================= */

/**
 * @brief 编码握手消息：hs_type(1) + hs_len(3) + hs_body
 */
int pqtls_hs_encode(uint8_t *out, uint32_t out_cap, uint8_t hs_type, const uint8_t *body, uint32_t body_len,
                    uint32_t *out_len)
{
    if (!out || !out_len) return -1;
    if (body_len > 0xFFFFFFu) return -1;
    if (4u + body_len > out_cap) return -1;

    out[0] = hs_type;
    pqtls_write_u24(out + 1, body_len);
    if (body_len != 0) {
        if (!body) return -1;
        memcpy(out + 4, body, body_len);
    }
    *out_len = 4u + body_len;
    return 0;
}

/**
 * @brief 从 record payload 中解析下一条握手消息（返回 body 指针与整条消息字节串范围）
 */
int pqtls_hs_decode_next(const uint8_t *payload, uint32_t payload_len, uint32_t *off,
                         uint8_t *hs_type, const uint8_t **hs_body, uint32_t *hs_body_len,
                         const uint8_t **hs_bytes, uint32_t *hs_bytes_len)
{
    if (!payload || !off || !hs_type || !hs_body || !hs_body_len || !hs_bytes || !hs_bytes_len) return -1;
    if (*off > payload_len) return -1;
    if (payload_len - *off < 4) return -1;

    const uint8_t *p = payload + *off;
    uint8_t t = p[0];
    uint32_t l = pqtls_read_u24(p + 1);
    if (l > payload_len - *off - 4u) return -1;

    *hs_type = t;
    *hs_body = p + 4;
    *hs_body_len = l;
    *hs_bytes = p;
    *hs_bytes_len = 4u + l;

    *off += 4u + l;
    return 0;
}
