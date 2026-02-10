#include "pqtls.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "net.h"
#include "pqtls_codec.h"
#include "pqtls_crypto.h"
#include "pqtls_defs.h"
#include "pqtls_keyschedule.h"
#include "pqtls_sm9_auth.h"
#include "scloud_kem.h"
#include "sm9_utils.h"

#include "crypto/crypt_eal_rand.h"
#include "crypto/crypt_errno.h"

#define PQTLS_MAX_TRANSCRIPT (MAX_PAYLOAD * 2u)

typedef struct {
    uint8_t data[PQTLS_MAX_TRANSCRIPT];
    uint32_t len;
} PQTLS_Transcript;

typedef struct {
    uint16_t version;
    uint8_t random[PQTLS_RANDOM_LEN];
    uint8_t sign_id[ID_MAX_LEN];
    uint16_t sign_id_len;
    uint8_t supported_kem[16];
    uint16_t supported_kem_len;
    uint8_t supported_aead[16];
    uint16_t supported_aead_len;
    uint8_t supported_hash[16];
    uint16_t supported_hash_len;
} ParsedClientHello;

typedef struct {
    uint16_t version;
    uint8_t random[PQTLS_RANDOM_LEN];
    uint8_t sign_id[ID_MAX_LEN];
    uint16_t sign_id_len;
    uint8_t selected_kem;
    uint8_t selected_aead;
    uint8_t selected_hash;
    const uint8_t *kem_pub;
    uint16_t kem_pub_len;
} ParsedServerHello;

typedef struct {
    uint8_t role;
    uint8_t sign_id[ID_MAX_LEN];
    uint16_t sign_id_len;
    const uint8_t *sig;
    uint16_t sig_len;
} ParsedCertVerify;

typedef struct {
    const uint8_t *ct;
    uint16_t ct_len;
} ParsedClientKem;

typedef struct {
    uint8_t role;
    uint8_t verify_data[PQTLS_SM3_LEN];
} ParsedFinished;

/**
 * @brief 将握手消息（header+body）追加到 transcript
 */
static int transcript_append(PQTLS_Transcript *t, const uint8_t *hs_bytes, uint32_t hs_len)
{
    if (!t || !hs_bytes || hs_len == 0) return -1;
    if (t->len + hs_len > sizeof(t->data)) return -1;
    memcpy(t->data + t->len, hs_bytes, hs_len);
    t->len += hs_len;
    return 0;
}

/**
 * @brief 计算 transcript 的 SM3 hash（32 bytes）
 */
static int transcript_hash(const PQTLS_Transcript *t, uint8_t out[PQTLS_SM3_LEN])
{
    if (!t || !out) return -1;
    return pqtls_sm3(t->data, t->len, out);
}

/**
 * @brief 生成安全随机数（优先使用已初始化的 openHiTLS RAND；失败则尝试初始化再生成）
 */
static int rand_bytes(uint8_t *out, uint32_t len)
{
    if (!out || len == 0) return -1;
    int32_t ret = CRYPT_EAL_Randbytes(out, len);
    if (ret == CRYPT_SUCCESS) return 0;

    /* 兼容：若上层未调用 scloud_global_init() 初始化 RAND，这里补一次 */
    (void)CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    ret = CRYPT_EAL_Randbytes(out, len);
    return (ret == CRYPT_SUCCESS) ? 0 : -1;
}

/**
 * @brief 将 UTF-8 ID（字节串）安全转换为 C 字符串（用于 SM9 验签接口）
 */
static int id_bytes_to_cstr(const uint8_t *id, uint16_t id_len, char out[ID_MAX_LEN + 1])
{
    if (!id || id_len == 0 || id_len > ID_MAX_LEN || !out) return -1;
    if (memchr(id, 0x00, id_len) != NULL) return -1;
    memcpy(out, id, id_len);
    out[id_len] = '\0';
    return 0;
}

/**
 * @brief KEM_ID -> SCloud+ secbits 映射
 */
static int kem_id_to_secbits(uint8_t kem_id, uint32_t *out_secbits)
{
    if (!out_secbits) return -1;
    switch (kem_id) {
        case PQTLS_KEM_SCLOUDPLUS_128: *out_secbits = SCLOUDPLUS_SECBITS1; return 0;
        case PQTLS_KEM_SCLOUDPLUS_192: *out_secbits = SCLOUDPLUS_SECBITS2; return 0;
        case PQTLS_KEM_SCLOUDPLUS_256: *out_secbits = SCLOUDPLUS_SECBITS3; return 0;
        default: return -1;
    }
}

/**
 * @brief 判断列表 TLV 中是否包含指定算法 ID（uint8 列表）
 */
static int list_contains_u8(const uint8_t *list, uint16_t list_len, uint8_t v)
{
    if (!list || list_len == 0) return 0;
    for (uint16_t i = 0; i < list_len; i++) if (list[i] == v) return 1;
    return 0;
}

/**
 * @brief 解析 CLIENT_HELLO body（TLV）
 */
static int parse_client_hello(const uint8_t *body, uint32_t body_len, ParsedClientHello *out)
{
    if (!body || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t off = 0;
    PQTLS_Tlv tlv;

    int have_ver = 0, have_rand = 0, have_id = 0, have_kem = 0, have_aead = 0, have_hash = 0;
    while (off < body_len) {
        if (pqtls_tlv_next(body, body_len, &off, &tlv) != 0) return -1;
        switch (tlv.t) {
            case PQTLS_TLV_VERSION:
                if (have_ver || tlv.l != 2) return -1;
                out->version = pqtls_read_u16(tlv.v);
                have_ver = 1;
                break;
            case PQTLS_TLV_RANDOM:
                if (have_rand || tlv.l != PQTLS_RANDOM_LEN) return -1;
                memcpy(out->random, tlv.v, PQTLS_RANDOM_LEN);
                have_rand = 1;
                break;
            case PQTLS_TLV_SIGN_ID:
                if (have_id || tlv.l == 0 || tlv.l > ID_MAX_LEN) return -1;
                memcpy(out->sign_id, tlv.v, tlv.l);
                out->sign_id_len = tlv.l;
                have_id = 1;
                break;
            case PQTLS_TLV_SUPPORTED_KEM:
                if (have_kem || tlv.l == 0 || tlv.l > sizeof(out->supported_kem)) return -1;
                memcpy(out->supported_kem, tlv.v, tlv.l);
                out->supported_kem_len = tlv.l;
                have_kem = 1;
                break;
            case PQTLS_TLV_SUPPORTED_AEAD:
                if (have_aead || tlv.l == 0 || tlv.l > sizeof(out->supported_aead)) return -1;
                memcpy(out->supported_aead, tlv.v, tlv.l);
                out->supported_aead_len = tlv.l;
                have_aead = 1;
                break;
            case PQTLS_TLV_SUPPORTED_HASH:
                if (have_hash || tlv.l == 0 || tlv.l > sizeof(out->supported_hash)) return -1;
                memcpy(out->supported_hash, tlv.v, tlv.l);
                out->supported_hash_len = tlv.l;
                have_hash = 1;
                break;
            default:
                /* 未知 TLV：必须忽略（向前兼容） */
                break;
        }
    }

    if (!have_ver || !have_rand || !have_id || !have_kem || !have_aead || !have_hash) return -1;
    return 0;
}

/**
 * @brief 解析 SERVER_HELLO body（TLV）
 */
static int parse_server_hello(const uint8_t *body, uint32_t body_len, ParsedServerHello *out)
{
    if (!body || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t off = 0;
    PQTLS_Tlv tlv;

    int have_ver = 0, have_rand = 0, have_id = 0;
    int have_kem = 0, have_aead = 0, have_hash = 0, have_pub = 0;
    while (off < body_len) {
        if (pqtls_tlv_next(body, body_len, &off, &tlv) != 0) return -1;
        switch (tlv.t) {
            case PQTLS_TLV_VERSION:
                if (have_ver || tlv.l != 2) return -1;
                out->version = pqtls_read_u16(tlv.v);
                have_ver = 1;
                break;
            case PQTLS_TLV_RANDOM:
                if (have_rand || tlv.l != PQTLS_RANDOM_LEN) return -1;
                memcpy(out->random, tlv.v, PQTLS_RANDOM_LEN);
                have_rand = 1;
                break;
            case PQTLS_TLV_SIGN_ID:
                if (have_id || tlv.l == 0 || tlv.l > ID_MAX_LEN) return -1;
                memcpy(out->sign_id, tlv.v, tlv.l);
                out->sign_id_len = tlv.l;
                have_id = 1;
                break;
            case PQTLS_TLV_SELECTED_KEM:
                if (have_kem || tlv.l != 1) return -1;
                out->selected_kem = tlv.v[0];
                have_kem = 1;
                break;
            case PQTLS_TLV_SELECTED_AEAD:
                if (have_aead || tlv.l != 1) return -1;
                out->selected_aead = tlv.v[0];
                have_aead = 1;
                break;
            case PQTLS_TLV_SELECTED_HASH:
                if (have_hash || tlv.l != 1) return -1;
                out->selected_hash = tlv.v[0];
                have_hash = 1;
                break;
            case PQTLS_TLV_KEM_PUBKEY:
                if (have_pub || tlv.l == 0) return -1;
                out->kem_pub = tlv.v;
                out->kem_pub_len = tlv.l;
                have_pub = 1;
                break;
            default:
                break;
        }
    }

    if (!have_ver || !have_rand || !have_id || !have_kem || !have_aead || !have_hash || !have_pub) return -1;
    return 0;
}

/**
 * @brief 解析 SM9_CERT_VERIFY body（TLV）
 */
static int parse_cert_verify(const uint8_t *body, uint32_t body_len, ParsedCertVerify *out)
{
    if (!body || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t off = 0;
    PQTLS_Tlv tlv;

    int have_role = 0, have_id = 0, have_sig = 0;
    while (off < body_len) {
        if (pqtls_tlv_next(body, body_len, &off, &tlv) != 0) return -1;
        switch (tlv.t) {
            case PQTLS_TLV_SIG_ROLE:
                if (have_role || tlv.l != 1) return -1;
                out->role = tlv.v[0];
                have_role = 1;
                break;
            case PQTLS_TLV_SIGN_ID:
                if (have_id || tlv.l == 0 || tlv.l > ID_MAX_LEN) return -1;
                memcpy(out->sign_id, tlv.v, tlv.l);
                out->sign_id_len = tlv.l;
                have_id = 1;
                break;
            case PQTLS_TLV_SIGNATURE:
                if (have_sig || tlv.l == 0) return -1;
                out->sig = tlv.v;
                out->sig_len = tlv.l;
                have_sig = 1;
                break;
            default:
                break;
        }
    }

    if (!have_role || !have_id || !have_sig) return -1;
    return 0;
}

/**
 * @brief 解析 CLIENT_KEM body（TLV）
 */
static int parse_client_kem(const uint8_t *body, uint32_t body_len, ParsedClientKem *out)
{
    if (!body || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t off = 0;
    PQTLS_Tlv tlv;
    int have_ct = 0;
    while (off < body_len) {
        if (pqtls_tlv_next(body, body_len, &off, &tlv) != 0) return -1;
        if (tlv.t == PQTLS_TLV_KEM_CIPHERTEXT) {
            if (have_ct || tlv.l == 0) return -1;
            out->ct = tlv.v;
            out->ct_len = tlv.l;
            have_ct = 1;
        }
    }
    return have_ct ? 0 : -1;
}

/**
 * @brief 解析 FINISHED body（TLV）
 */
static int parse_finished(const uint8_t *body, uint32_t body_len, ParsedFinished *out)
{
    if (!body || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t off = 0;
    PQTLS_Tlv tlv;
    int have_role = 0, have_vd = 0;
    while (off < body_len) {
        if (pqtls_tlv_next(body, body_len, &off, &tlv) != 0) return -1;
        switch (tlv.t) {
            case PQTLS_TLV_SIG_ROLE:
                if (have_role || tlv.l != 1) return -1;
                out->role = tlv.v[0];
                have_role = 1;
                break;
            case PQTLS_TLV_VERIFY_DATA:
                if (have_vd || tlv.l != PQTLS_SM3_LEN) return -1;
                memcpy(out->verify_data, tlv.v, PQTLS_SM3_LEN);
                have_vd = 1;
                break;
            default:
                break;
        }
    }

    if (!have_role || !have_vd) return -1;
    return 0;
}

/**
 * @brief 构造 CLIENT_HELLO body（TLV）
 */
static int build_client_hello_body(uint8_t *out, uint32_t out_cap, const uint8_t client_random[PQTLS_RANDOM_LEN],
                                   const uint8_t *client_id, uint16_t client_id_len, uint32_t *out_len)
{
    if (!out || !client_random || !client_id || client_id_len == 0 || !out_len) return -1;
    PQTLS_Buffer b;
    pqtls_buf_init(&b, out, out_cap);

    uint8_t kems[1]  = {PQTLS_KEM_SCLOUDPLUS_128};
    uint8_t aeads[1] = {PQTLS_AEAD_SM4_GCM_128};
    uint8_t hashs[1] = {PQTLS_HASH_SM3};

    if (pqtls_tlv_append_u16(&b, PQTLS_TLV_VERSION, PQTLS_VERSION_V1) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_RANDOM, client_random, PQTLS_RANDOM_LEN) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SIGN_ID, client_id, client_id_len) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SUPPORTED_KEM, kems, sizeof(kems)) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SUPPORTED_AEAD, aeads, sizeof(aeads)) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SUPPORTED_HASH, hashs, sizeof(hashs)) != 0) return -1;

    *out_len = b.len;
    return 0;
}

/**
 * @brief 构造 SERVER_HELLO body（TLV）
 */
static int build_server_hello_body(uint8_t *out, uint32_t out_cap, const uint8_t server_random[PQTLS_RANDOM_LEN],
                                   const uint8_t *server_id, uint16_t server_id_len,
                                   uint8_t kem_id, uint8_t aead_id, uint8_t hash_id,
                                   const uint8_t *kem_pub, uint16_t kem_pub_len,
                                   uint32_t *out_len)
{
    if (!out || !server_random || !server_id || server_id_len == 0 || !kem_pub || kem_pub_len == 0 || !out_len) return -1;
    PQTLS_Buffer b;
    pqtls_buf_init(&b, out, out_cap);

    if (pqtls_tlv_append_u16(&b, PQTLS_TLV_VERSION, PQTLS_VERSION_V1) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_RANDOM, server_random, PQTLS_RANDOM_LEN) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SIGN_ID, server_id, server_id_len) != 0) return -1;
    if (pqtls_tlv_append_u8(&b, PQTLS_TLV_SELECTED_KEM, kem_id) != 0) return -1;
    if (pqtls_tlv_append_u8(&b, PQTLS_TLV_SELECTED_AEAD, aead_id) != 0) return -1;
    if (pqtls_tlv_append_u8(&b, PQTLS_TLV_SELECTED_HASH, hash_id) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_KEM_PUBKEY, kem_pub, kem_pub_len) != 0) return -1;

    *out_len = b.len;
    return 0;
}

/**
 * @brief 构造 CLIENT_KEM body（TLV）
 */
static int build_client_kem_body(uint8_t *out, uint32_t out_cap, const uint8_t *ct, uint16_t ct_len, uint32_t *out_len)
{
    if (!out || !ct || ct_len == 0 || !out_len) return -1;
    PQTLS_Buffer b;
    pqtls_buf_init(&b, out, out_cap);
    if (pqtls_tlv_append(&b, PQTLS_TLV_KEM_CIPHERTEXT, ct, ct_len) != 0) return -1;
    *out_len = b.len;
    return 0;
}

/**
 * @brief 构造 SM9_CERT_VERIFY body（TLV）
 */
static int build_cert_verify_body(uint8_t *out, uint32_t out_cap, PQTLS_Role role,
                                  const uint8_t *sign_id, uint16_t sign_id_len,
                                  const uint8_t thash[PQTLS_SM3_LEN],
                                  const SM9_SIGN_KEY *sign_key, uint32_t *out_len)
{
    if (!out || !sign_id || sign_id_len == 0 || !thash || !sign_key || !out_len) return -1;

    uint8_t sig[512];
    uint32_t sig_len = sizeof(sig);
    if (pqtls_sm9_sign_cert_verify(role, thash, sig, &sig_len, sign_key) != 0) return -1;

    PQTLS_Buffer b;
    pqtls_buf_init(&b, out, out_cap);
    if (pqtls_tlv_append_u8(&b, PQTLS_TLV_SIG_ROLE, (uint8_t)role) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SIGN_ID, sign_id, sign_id_len) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_SIGNATURE, sig, (uint16_t)sig_len) != 0) return -1;

    pqtls_secure_clear(sig, sizeof(sig));
    *out_len = b.len;
    return 0;
}

/**
 * @brief 构造 FINISHED body（TLV）
 */
static int build_finished_body(uint8_t *out, uint32_t out_cap, PQTLS_Role role,
                               const uint8_t verify_data[PQTLS_SM3_LEN], uint32_t *out_len)
{
    if (!out || !verify_data || !out_len) return -1;
    PQTLS_Buffer b;
    pqtls_buf_init(&b, out, out_cap);
    if (pqtls_tlv_append_u8(&b, PQTLS_TLV_SIG_ROLE, (uint8_t)role) != 0) return -1;
    if (pqtls_tlv_append(&b, PQTLS_TLV_VERIFY_DATA, verify_data, PQTLS_SM3_LEN) != 0) return -1;
    *out_len = b.len;
    return 0;
}

/**
 * @brief 在 record payload 中追加一条握手消息，并返回该消息的原始字节串指针与长度
 */
static int rec_append_handshake(PQTLS_Buffer *rec, uint8_t hs_type, const uint8_t *body, uint32_t body_len,
                                const uint8_t **out_hs_bytes, uint32_t *out_hs_bytes_len)
{
    if (!rec || !out_hs_bytes || !out_hs_bytes_len) return -1;
    if (!body && body_len != 0) return -1;
    if (body_len > 0xFFFFFFu) return -1;

    uint32_t start = rec->len;
    if (pqtls_buf_append_u8(rec, hs_type) != 0) return -1;
    if (pqtls_buf_append_u24(rec, body_len) != 0) return -1;
    if (body_len != 0) {
        if (pqtls_buf_append(rec, body, body_len) != 0) return -1;
    }
    *out_hs_bytes = rec->data + start;
    *out_hs_bytes_len = rec->len - start;
    return 0;
}

/**
 * @brief 发送一个明文握手 record（REC_HANDSHAKE）
 */
static int send_handshake_record(int fd, const uint8_t *payload, uint32_t payload_len)
{
    if (!payload || payload_len == 0) return APP_ERR;
    return net_send_packet(fd, PQTLS_REC_HANDSHAKE, payload, payload_len);
}

/**
 * @brief 接收一个明文握手 record（REC_HANDSHAKE）
 */
static int recv_handshake_record(int fd, uint8_t *payload, uint32_t payload_cap, uint32_t *payload_len)
{
    if (!payload || !payload_len) return APP_ERR;
    uint16_t type = 0;
    uint32_t len = 0;
    if (net_recv_packet(fd, &type, payload, &len, payload_cap) != APP_OK) return APP_ERR;
    if (type != PQTLS_REC_HANDSHAKE) return APP_ERR;
    *payload_len = len;
    return APP_OK;
}

int pqtls_client_handshake(int fd, const char *client_id_utf8, const char *expected_server_id_utf8,
                           PQTLS_Session *sess)
{
    if (!sess || !client_id_utf8 || !expected_server_id_utf8) return APP_ERR;

    memset(sess, 0, sizeof(*sess));
    sess->is_client = true;

    size_t client_id_len = strlen(client_id_utf8);
    size_t expected_srv_id_len = strlen(expected_server_id_utf8);
    if (client_id_len == 0 || client_id_len > ID_MAX_LEN) return APP_ERR;
    if (expected_srv_id_len == 0 || expected_srv_id_len > ID_MAX_LEN) return APP_ERR;

    memcpy(sess->client_id, client_id_utf8, client_id_len);
    sess->client_id_len = (uint16_t)client_id_len;

    /* 预期的 server_id 先存下来，后续对比 */
    memcpy(sess->server_id, expected_server_id_utf8, expected_srv_id_len);
    sess->server_id_len = (uint16_t)expected_srv_id_len;

    /* 预加载 SM9 主公钥与客户端签名私钥 */
    SM9_SIGN_MASTER_KEY mpk;
    if (load_sm9_master_pub_key(&mpk) != APP_OK) return APP_ERR;

    SM9_SIGN_KEY client_sign_key;
    if (load_sm9_sign_key_from_file(&client_sign_key, SM9_CLIENT_SIGN_KEY_PATH) != APP_OK) return APP_ERR;

    /* 1) 发送 CLIENT_HELLO */
    if (rand_bytes(sess->client_random, PQTLS_RANDOM_LEN) != 0) return APP_ERR;

    uint8_t ch_body[512];
    uint32_t ch_body_len = 0;
    if (build_client_hello_body(ch_body, sizeof(ch_body), sess->client_random,
                                sess->client_id, sess->client_id_len, &ch_body_len) != 0) return APP_ERR;

    uint8_t ch_msg[1024];
    uint32_t ch_msg_len = 0;
    if (pqtls_hs_encode(ch_msg, sizeof(ch_msg), PQTLS_HS_CLIENT_HELLO, ch_body, ch_body_len, &ch_msg_len) != 0) return APP_ERR;

    PQTLS_Transcript tr = {0};
    if (transcript_append(&tr, ch_msg, ch_msg_len) != 0) return APP_ERR;

    if (send_handshake_record(fd, ch_msg, ch_msg_len) != APP_OK) return APP_ERR;

    /* 2) 接收 SERVER_HELLO + SM9_CERT_VERIFY(server) */
    uint8_t srv_rec[MAX_PAYLOAD];
    uint32_t srv_rec_len = 0;
    if (recv_handshake_record(fd, srv_rec, sizeof(srv_rec), &srv_rec_len) != APP_OK) return APP_ERR;

    uint32_t off = 0;
    uint8_t hs_type = 0;
    const uint8_t *hs_body = NULL;
    uint32_t hs_body_len = 0;
    const uint8_t *hs_bytes = NULL;
    uint32_t hs_bytes_len = 0;

    /* 2.1 SERVER_HELLO */
    if (pqtls_hs_decode_next(srv_rec, srv_rec_len, &off, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) return APP_ERR;
    if (hs_type != PQTLS_HS_SERVER_HELLO) return APP_ERR;

    ParsedServerHello sh;
    if (parse_server_hello(hs_body, hs_body_len, &sh) != 0) return APP_ERR;
    if (sh.version != PQTLS_VERSION_V1) return APP_ERR;

    /* 检查 server_id 是否与预期一致 */
    if (sh.sign_id_len != sess->server_id_len || memcmp(sh.sign_id, sess->server_id, sess->server_id_len) != 0) return APP_ERR;

    memcpy(sess->server_random, sh.random, PQTLS_RANDOM_LEN);
    sess->kem_id = sh.selected_kem;
    sess->aead_id = sh.selected_aead;
    sess->hash_id = sh.selected_hash;
    if (sess->kem_id != PQTLS_KEM_SCLOUDPLUS_128) return APP_ERR;
    if (sess->aead_id != PQTLS_AEAD_SM4_GCM_128) return APP_ERR;
    if (sess->hash_id != PQTLS_HASH_SM3) return APP_ERR;

    /* 保存 KEM 公钥（后续封装用） */
    uint8_t *kem_pub = (uint8_t *)malloc(sh.kem_pub_len);
    if (!kem_pub) return APP_ERR;
    memcpy(kem_pub, sh.kem_pub, sh.kem_pub_len);
    uint16_t kem_pub_len = sh.kem_pub_len;

    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) { free(kem_pub); return APP_ERR; }

    /* 2.2 CERT_VERIFY(server) */
    if (pqtls_hs_decode_next(srv_rec, srv_rec_len, &off, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) { free(kem_pub); return APP_ERR; }
    if (hs_type != PQTLS_HS_SM9_CERT_VERIFY) { free(kem_pub); return APP_ERR; }

    ParsedCertVerify cv_srv;
    if (parse_cert_verify(hs_body, hs_body_len, &cv_srv) != 0) { free(kem_pub); return APP_ERR; }
    if (cv_srv.role != PQTLS_ROLE_SERVER) { free(kem_pub); return APP_ERR; }
    if (cv_srv.sign_id_len != sess->server_id_len || memcmp(cv_srv.sign_id, sess->server_id, sess->server_id_len) != 0) { free(kem_pub); return APP_ERR; }

    uint8_t thash_srv_cv[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_srv_cv) != 0) { free(kem_pub); return APP_ERR; }

    char srv_id_cstr[ID_MAX_LEN + 1];
    if (id_bytes_to_cstr(sess->server_id, sess->server_id_len, srv_id_cstr) != 0) { free(kem_pub); return APP_ERR; }

    if (pqtls_sm9_verify_cert_verify(PQTLS_ROLE_SERVER, thash_srv_cv, cv_srv.sig, cv_srv.sig_len, &mpk, srv_id_cstr) != 0) {
        free(kem_pub);
        return APP_ERR;
    }

    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) { free(kem_pub); return APP_ERR; }

    if (off != srv_rec_len) { free(kem_pub); return APP_ERR; }

    /* 3) CLIENT_KEM + CERT_VERIFY(client) + FINISHED(client) */
    uint32_t secbits = 0;
    if (kem_id_to_secbits(sess->kem_id, &secbits) != 0) { free(kem_pub); return APP_ERR; }

    SCloudCtx sc = {0};
    uint8_t ct[MAX_PAYLOAD];
    uint32_t ct_len = sizeof(ct);
    sess->k_pqc_len = sizeof(sess->k_pqc);
    if (scloud_obu_encaps(&sc, secbits, kem_pub, kem_pub_len, ct, &ct_len, sess->k_pqc, &sess->k_pqc_len) != APP_OK) {
        free(kem_pub);
        scloud_ctx_free(&sc);
        return APP_ERR;
    }
    scloud_ctx_free(&sc);
    free(kem_pub);

    uint8_t rec_payload[MAX_PAYLOAD];
    PQTLS_Buffer rec;
    pqtls_buf_init(&rec, rec_payload, sizeof(rec_payload));

    /* 3.1 CLIENT_KEM */
    uint8_t ckem_body[MAX_PAYLOAD];
    uint32_t ckem_body_len = 0;
    if (build_client_kem_body(ckem_body, sizeof(ckem_body), ct, (uint16_t)ct_len, &ckem_body_len) != 0) return APP_ERR;

    const uint8_t *ckem_bytes = NULL;
    uint32_t ckem_bytes_len = 0;
    if (rec_append_handshake(&rec, PQTLS_HS_CLIENT_KEM, ckem_body, ckem_body_len, &ckem_bytes, &ckem_bytes_len) != 0) return APP_ERR;
    if (transcript_append(&tr, ckem_bytes, ckem_bytes_len) != 0) return APP_ERR;

    /* 3.2 CERT_VERIFY(client) */
    uint8_t thash_cli_cv[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_cli_cv) != 0) return APP_ERR;

    uint8_t cv_cli_body[1024];
    uint32_t cv_cli_body_len = 0;
    if (build_cert_verify_body(cv_cli_body, sizeof(cv_cli_body), PQTLS_ROLE_CLIENT,
                               sess->client_id, sess->client_id_len,
                               thash_cli_cv, &client_sign_key, &cv_cli_body_len) != 0) return APP_ERR;

    const uint8_t *cv_cli_bytes = NULL;
    uint32_t cv_cli_bytes_len = 0;
    if (rec_append_handshake(&rec, PQTLS_HS_SM9_CERT_VERIFY, cv_cli_body, cv_cli_body_len, &cv_cli_bytes, &cv_cli_bytes_len) != 0) return APP_ERR;
    if (transcript_append(&tr, cv_cli_bytes, cv_cli_bytes_len) != 0) return APP_ERR;

    /* 3.3 Key schedule + FINISHED(client) */
    uint8_t thash_key[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_key) != 0) return APP_ERR;

    uint8_t finished_key_c2s[PQTLS_SM3_LEN];
    uint8_t finished_key_s2c[PQTLS_SM3_LEN];
    if (pqtls_derive_secrets(sess->k_pqc, sess->k_pqc_len, sess->client_random, sess->server_random, thash_key,
                             finished_key_c2s, finished_key_s2c,
                             sess->app_key_c2s, sess->app_iv_c2s,
                             sess->app_key_s2c, sess->app_iv_s2c) != 0) return APP_ERR;

    uint8_t vd_cli[PQTLS_SM3_LEN];
    if (pqtls_calc_finished_verify_data(finished_key_c2s, thash_key, vd_cli) != 0) return APP_ERR;

    uint8_t fin_cli_body[64];
    uint32_t fin_cli_body_len = 0;
    if (build_finished_body(fin_cli_body, sizeof(fin_cli_body), PQTLS_ROLE_CLIENT, vd_cli, &fin_cli_body_len) != 0) return APP_ERR;

    const uint8_t *fin_cli_bytes = NULL;
    uint32_t fin_cli_bytes_len = 0;
    if (rec_append_handshake(&rec, PQTLS_HS_FINISHED, fin_cli_body, fin_cli_body_len, &fin_cli_bytes, &fin_cli_bytes_len) != 0) return APP_ERR;
    if (transcript_append(&tr, fin_cli_bytes, fin_cli_bytes_len) != 0) return APP_ERR;

    if (send_handshake_record(fd, rec.data, rec.len) != APP_OK) return APP_ERR;

    /* 4) 接收 FINISHED(server) */
    uint8_t fin_rec[MAX_PAYLOAD];
    uint32_t fin_rec_len = 0;
    if (recv_handshake_record(fd, fin_rec, sizeof(fin_rec), &fin_rec_len) != APP_OK) return APP_ERR;

    uint32_t off2 = 0;
    if (pqtls_hs_decode_next(fin_rec, fin_rec_len, &off2, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) return APP_ERR;
    if (hs_type != PQTLS_HS_FINISHED) return APP_ERR;
    if (off2 != fin_rec_len) return APP_ERR;

    ParsedFinished fin_srv;
    if (parse_finished(hs_body, hs_body_len, &fin_srv) != 0) return APP_ERR;
    if (fin_srv.role != PQTLS_ROLE_SERVER) return APP_ERR;

    uint8_t thash_before_srv_fin[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_before_srv_fin) != 0) return APP_ERR;

    uint8_t expect_vd_srv[PQTLS_SM3_LEN];
    if (pqtls_calc_finished_verify_data(finished_key_s2c, thash_before_srv_fin, expect_vd_srv) != 0) return APP_ERR;
    if (pqtls_ct_memcmp(expect_vd_srv, fin_srv.verify_data, PQTLS_SM3_LEN) != 0) return APP_ERR;

    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) return APP_ERR;

    pqtls_secure_clear(finished_key_c2s, sizeof(finished_key_c2s));
    pqtls_secure_clear(finished_key_s2c, sizeof(finished_key_s2c));
    pqtls_secure_clear(expect_vd_srv, sizeof(expect_vd_srv));

    sess->send_seq = 0;
    sess->recv_seq = 0;
    return APP_OK;
}

int pqtls_server_handshake(int fd, const char *expected_client_id_utf8, const char *server_id_utf8,
                           PQTLS_Session *sess)
{
    if (!sess || !expected_client_id_utf8 || !server_id_utf8) return APP_ERR;

    memset(sess, 0, sizeof(*sess));
    sess->is_client = false;

    size_t expected_cli_len = strlen(expected_client_id_utf8);
    size_t server_id_len = strlen(server_id_utf8);
    if (expected_cli_len == 0 || expected_cli_len > ID_MAX_LEN) return APP_ERR;
    if (server_id_len == 0 || server_id_len > ID_MAX_LEN) return APP_ERR;

    /* 本端 server_id */
    memcpy(sess->server_id, server_id_utf8, server_id_len);
    sess->server_id_len = (uint16_t)server_id_len;

    /* 预加载 SM9 主公钥与服务端签名私钥 */
    SM9_SIGN_MASTER_KEY mpk;
    if (load_sm9_master_pub_key(&mpk) != APP_OK) return APP_ERR;

    SM9_SIGN_KEY server_sign_key;
    if (load_sm9_sign_key_from_file(&server_sign_key, SM9_SERVER_SIGN_KEY_PATH) != APP_OK) return APP_ERR;

    PQTLS_Transcript tr = {0};

    /* 1) 接收 CLIENT_HELLO */
    uint8_t cli_rec[MAX_PAYLOAD];
    uint32_t cli_rec_len = 0;
    if (recv_handshake_record(fd, cli_rec, sizeof(cli_rec), &cli_rec_len) != APP_OK) return APP_ERR;

    uint32_t off = 0;
    uint8_t hs_type = 0;
    const uint8_t *hs_body = NULL;
    uint32_t hs_body_len = 0;
    const uint8_t *hs_bytes = NULL;
    uint32_t hs_bytes_len = 0;

    if (pqtls_hs_decode_next(cli_rec, cli_rec_len, &off, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) return APP_ERR;
    if (hs_type != PQTLS_HS_CLIENT_HELLO) return APP_ERR;
    if (off != cli_rec_len) return APP_ERR;

    ParsedClientHello ch;
    if (parse_client_hello(hs_body, hs_body_len, &ch) != 0) return APP_ERR;
    if (ch.version != PQTLS_VERSION_V1) return APP_ERR;

    /* 校验 client_id 是否符合预期 */
    if (ch.sign_id_len != expected_cli_len || memcmp(ch.sign_id, expected_client_id_utf8, expected_cli_len) != 0) return APP_ERR;

    /* 保存 client_random / client_id */
    memcpy(sess->client_random, ch.random, PQTLS_RANDOM_LEN);
    memcpy(sess->client_id, ch.sign_id, ch.sign_id_len);
    sess->client_id_len = ch.sign_id_len;

    /* 协商：本实现固定只支持 128 + SM4-GCM + SM3 */
    if (!list_contains_u8(ch.supported_kem, ch.supported_kem_len, PQTLS_KEM_SCLOUDPLUS_128)) return APP_ERR;
    if (!list_contains_u8(ch.supported_aead, ch.supported_aead_len, PQTLS_AEAD_SM4_GCM_128)) return APP_ERR;
    if (!list_contains_u8(ch.supported_hash, ch.supported_hash_len, PQTLS_HASH_SM3)) return APP_ERR;

    sess->kem_id = PQTLS_KEM_SCLOUDPLUS_128;
    sess->aead_id = PQTLS_AEAD_SM4_GCM_128;
    sess->hash_id = PQTLS_HASH_SM3;

    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) return APP_ERR;

    /* 2) 生成 server_random 与一次性 KEM keypair */
    if (rand_bytes(sess->server_random, PQTLS_RANDOM_LEN) != 0) return APP_ERR;

    uint32_t secbits = 0;
    if (kem_id_to_secbits(sess->kem_id, &secbits) != 0) return APP_ERR;

    SCloudCtx sc = {0};
    uint8_t kem_pub[MAX_PAYLOAD];
    uint8_t kem_prv[MAX_PAYLOAD];
    if (scloud_rsu_keygen(&sc, secbits, kem_pub, sizeof(kem_pub), kem_prv, sizeof(kem_prv)) != APP_OK) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }

    /* 3) 发送 SERVER_HELLO + CERT_VERIFY(server) */
    uint8_t sh_body[MAX_PAYLOAD];
    uint32_t sh_body_len = 0;
    if (build_server_hello_body(sh_body, sizeof(sh_body), sess->server_random,
                                sess->server_id, sess->server_id_len,
                                sess->kem_id, sess->aead_id, sess->hash_id,
                                kem_pub, (uint16_t)sc.pk_len, &sh_body_len) != 0) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }

    uint8_t rec_payload[MAX_PAYLOAD];
    PQTLS_Buffer rec;
    pqtls_buf_init(&rec, rec_payload, sizeof(rec_payload));

    const uint8_t *sh_bytes = NULL;
    uint32_t sh_bytes_len = 0;
    if (rec_append_handshake(&rec, PQTLS_HS_SERVER_HELLO, sh_body, sh_body_len, &sh_bytes, &sh_bytes_len) != 0) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }
    if (transcript_append(&tr, sh_bytes, sh_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t thash_srv_cv[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_srv_cv) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t cv_srv_body[1024];
    uint32_t cv_srv_body_len = 0;
    if (build_cert_verify_body(cv_srv_body, sizeof(cv_srv_body), PQTLS_ROLE_SERVER,
                               sess->server_id, sess->server_id_len,
                               thash_srv_cv, &server_sign_key, &cv_srv_body_len) != 0) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }

    const uint8_t *cv_srv_bytes = NULL;
    uint32_t cv_srv_bytes_len = 0;
    if (rec_append_handshake(&rec, PQTLS_HS_SM9_CERT_VERIFY, cv_srv_body, cv_srv_body_len, &cv_srv_bytes, &cv_srv_bytes_len) != 0) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }
    if (transcript_append(&tr, cv_srv_bytes, cv_srv_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    if (send_handshake_record(fd, rec.data, rec.len) != APP_OK) { scloud_ctx_free(&sc); return APP_ERR; }

    /* 4) 接收 CLIENT_KEM + CERT_VERIFY(client) + FINISHED(client) */
    uint8_t cli2_rec[MAX_PAYLOAD];
    uint32_t cli2_rec_len = 0;
    if (recv_handshake_record(fd, cli2_rec, sizeof(cli2_rec), &cli2_rec_len) != APP_OK) { scloud_ctx_free(&sc); return APP_ERR; }

    uint32_t off2 = 0;

    /* 4.1 CLIENT_KEM */
    if (pqtls_hs_decode_next(cli2_rec, cli2_rec_len, &off2, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (hs_type != PQTLS_HS_CLIENT_KEM) { scloud_ctx_free(&sc); return APP_ERR; }

    ParsedClientKem ckem;
    if (parse_client_kem(hs_body, hs_body_len, &ckem) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    sess->k_pqc_len = sizeof(sess->k_pqc);
    if (scloud_rsu_decaps(&sc, secbits, kem_prv, sc.sk_len, ckem.ct, ckem.ct_len, sess->k_pqc, &sess->k_pqc_len) != APP_OK) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }

    /* 4.2 CERT_VERIFY(client) */
    if (pqtls_hs_decode_next(cli2_rec, cli2_rec_len, &off2, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (hs_type != PQTLS_HS_SM9_CERT_VERIFY) { scloud_ctx_free(&sc); return APP_ERR; }

    ParsedCertVerify cv_cli;
    if (parse_cert_verify(hs_body, hs_body_len, &cv_cli) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (cv_cli.role != PQTLS_ROLE_CLIENT) { scloud_ctx_free(&sc); return APP_ERR; }
    if (cv_cli.sign_id_len != sess->client_id_len || memcmp(cv_cli.sign_id, sess->client_id, sess->client_id_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t thash_cli_cv[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_cli_cv) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    char cli_id_cstr[ID_MAX_LEN + 1];
    if (id_bytes_to_cstr(sess->client_id, sess->client_id_len, cli_id_cstr) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    if (pqtls_sm9_verify_cert_verify(PQTLS_ROLE_CLIENT, thash_cli_cv, cv_cli.sig, cv_cli.sig_len, &mpk, cli_id_cstr) != 0) {
        scloud_ctx_free(&sc);
        return APP_ERR;
    }
    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    /* 派生 finished_key/app_key（thash_key = transcript before client Finished） */
    uint8_t thash_key[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_key) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t finished_key_c2s[PQTLS_SM3_LEN];
    uint8_t finished_key_s2c[PQTLS_SM3_LEN];
    if (pqtls_derive_secrets(sess->k_pqc, sess->k_pqc_len, sess->client_random, sess->server_random, thash_key,
                             finished_key_c2s, finished_key_s2c,
                             sess->app_key_c2s, sess->app_iv_c2s,
                             sess->app_key_s2c, sess->app_iv_s2c) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    /* 4.3 FINISHED(client) */
    if (pqtls_hs_decode_next(cli2_rec, cli2_rec_len, &off2, &hs_type, &hs_body, &hs_body_len, &hs_bytes, &hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (hs_type != PQTLS_HS_FINISHED) { scloud_ctx_free(&sc); return APP_ERR; }

    ParsedFinished fin_cli;
    if (parse_finished(hs_body, hs_body_len, &fin_cli) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (fin_cli.role != PQTLS_ROLE_CLIENT) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t expect_vd_cli[PQTLS_SM3_LEN];
    if (pqtls_calc_finished_verify_data(finished_key_c2s, thash_key, expect_vd_cli) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (pqtls_ct_memcmp(expect_vd_cli, fin_cli.verify_data, PQTLS_SM3_LEN) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    if (transcript_append(&tr, hs_bytes, hs_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (off2 != cli2_rec_len) { scloud_ctx_free(&sc); return APP_ERR; }

    /* 5) 发送 FINISHED(server) */
    uint8_t thash_before_srv_fin[PQTLS_SM3_LEN];
    if (transcript_hash(&tr, thash_before_srv_fin) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t vd_srv[PQTLS_SM3_LEN];
    if (pqtls_calc_finished_verify_data(finished_key_s2c, thash_before_srv_fin, vd_srv) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t fin_srv_body[64];
    uint32_t fin_srv_body_len = 0;
    if (build_finished_body(fin_srv_body, sizeof(fin_srv_body), PQTLS_ROLE_SERVER, vd_srv, &fin_srv_body_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    uint8_t fin_msg[MAX_PAYLOAD];
    PQTLS_Buffer fin_rec;
    pqtls_buf_init(&fin_rec, fin_msg, sizeof(fin_msg));
    const uint8_t *fin_bytes = NULL;
    uint32_t fin_bytes_len = 0;
    if (rec_append_handshake(&fin_rec, PQTLS_HS_FINISHED, fin_srv_body, fin_srv_body_len, &fin_bytes, &fin_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }

    if (transcript_append(&tr, fin_bytes, fin_bytes_len) != 0) { scloud_ctx_free(&sc); return APP_ERR; }
    if (send_handshake_record(fd, fin_rec.data, fin_rec.len) != APP_OK) { scloud_ctx_free(&sc); return APP_ERR; }

    pqtls_secure_clear(finished_key_c2s, sizeof(finished_key_c2s));
    pqtls_secure_clear(finished_key_s2c, sizeof(finished_key_s2c));
    pqtls_secure_clear(expect_vd_cli, sizeof(expect_vd_cli));

    pqtls_secure_clear(kem_prv, sizeof(kem_prv));
    scloud_ctx_free(&sc);

    sess->send_seq = 0;
    sess->recv_seq = 0;
    return APP_OK;
}
