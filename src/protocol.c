#include "protocol.h"
#include "net.h"
#include "scloud_kem.h"
#include "sm9_utils.h"
#include <string.h>
#include <stdio.h>

static int append_transcript(SessionKeys *ks, const void *data, uint32_t len) {
    if (ks->transcript_len + len > sizeof(ks->transcript)) 
    {
        printf("ERROR:Not enough space in the transcript buffer\n");
        return APP_ERR;
    }
    memcpy(ks->transcript + ks->transcript_len, data, len);
    ks->transcript_len += len;
    printf("[TRANSCRIPT] appended %u bytes, total length: %u\n", len, ks->transcript_len);
    return APP_OK;
}

int protocol_rsu_handshake(int fd, const char *obu_id, SessionKeys *ks) {
    int rc;
    uint16_t t; uint32_t l;
    uint8_t buf[MAX_PAYLOAD];

    // 等 OBU 的 HELLO
    rc = net_recv_packet(fd, &t, buf, &l, sizeof(buf));
    if (rc != APP_OK || t != MSG_HELLO) return APP_ERR;
    append_transcript(ks, &t, sizeof(t));
    printf("[TRANSCRIPT] appended HELLO message\n");

    // 生成 SCloud+ 密钥对
    SCloudCtx sc = {0};
    uint8_t rsu_pub[20000] = {0}, rsu_prv[20000] = {0};
    uint32_t pub_len = sizeof(rsu_pub), prv_len = sizeof(rsu_prv);

    if (scloud_rsu_keygen(&sc, SCLOUDPLUS_SECBITS1, rsu_pub, pub_len, rsu_prv, prv_len) != APP_OK)      
    {
        printf("scloud_rsu_keygen failed\n");
        return APP_ERR;
    }
    // 发送 KEM 公钥
    if (net_send_packet(fd, MSG_KEM_PUBKEY, rsu_pub, sc.pk_len) != APP_OK) 
    {
        printf("net_send_packet kem public failed\n");
        return APP_ERR;
    }
    printf("kem public key sent\n");
    printf("[TRANSCRIPT] appended RSU public key of length %u\n", sc.pk_len);
    append_transcript(ks, rsu_pub, sc.pk_len);

    // 接收 OBU 的密文
    rc = net_recv_packet(fd, &t, buf, &l, sizeof(buf));
    printf("net_recv_packet kem ciphertext: rc=%d, type=%u, len=%u\n", rc, t, l);
    if (rc != APP_OK || t != MSG_KEM_CIPHERTEXT) 
    {
        printf("net_recv_packet kem ciphertext failed\n");
        return APP_ERR;
    }
    append_transcript(ks, buf, l);

    // 解封得到 k_pqc
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_rsu_decaps(&sc, rsu_prv, sc.sk_len, buf, l, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;

    // 接收 OBU 的 SM9 签名并验证
    rc = net_recv_packet(fd, &t, buf, &l, sizeof(buf));
    if (rc != APP_OK || t != MSG_AUTH_SIGNATURE) return APP_ERR;

    // 获取 MPK
    uint8_t mpk[128]; uint32_t mpk_len = sizeof(mpk);
    if (sm9_get_mpk(mpk, &mpk_len) != APP_OK) return APP_ERR;

    if (sm9_verify(obu_id, mpk, mpk_len, ks->transcript, ks->transcript_len, buf, l) != APP_OK)
        return APP_ERR;

    // 混合密钥（此处先用 PQC 单独作为会话密钥；等你把 SM9 KDF 接上后，改为 mix 函数）
    ks->k_final_len = sizeof(ks->k_final);
    if (scloud_mix_keys_sha256(NULL, 0, ks->k_pqc, ks->k_pqc_len, ks->k_final, &ks->k_final_len) != APP_OK)
        return APP_ERR;

    // 回 ACK
    if (net_send_packet(fd, MSG_AUTH_VERIFY_OK, NULL, 0) != APP_OK) return APP_ERR;
    return APP_OK;
}

int protocol_obu_handshake(int fd, const char *obu_id, SessionKeys *ks) {
    // 1) 发送 HELLO
    if (net_send_packet(fd, MSG_HELLO, "hi", 2) != APP_OK) 
    {
        printf("net_send_packet hello failed\n");
        return APP_ERR;
    }
    append_transcript(ks, "hi", 2);

    // 2) 收 RSU 公钥
    uint16_t t; uint32_t l; uint8_t buf[MAX_PAYLOAD];
    if (net_recv_packet(fd, &t, buf, &l, sizeof(buf)) != APP_OK || t != MSG_KEM_PUBKEY) 
    {
        printf("net_recv_packet kem public failed\n");
        return APP_ERR;
    }
    append_transcript(ks, buf, l);
    //打印 RSU 公钥
    // printf("RSU 公钥：\n");
    // for (int i = 0; i < l; i++) {
    //     printf("%02x", buf[i]);
    // }
    // printf("\n");

    // 3) 封装得到密文和 k_pqc
    SCloudCtx sc = {0};
    uint8_t ct[20000] = {0}; uint32_t ct_len = sizeof(ct);
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_obu_encaps(&sc, buf, l, ct, &ct_len, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;

    // 发送密文
    if (net_send_packet(fd, MSG_KEM_CIPHERTEXT, ct, ct_len) != APP_OK) return APP_ERR;
    append_transcript(ks, ct, ct_len);

    // 4) OBU 对 transcript 做 SM9 签名并发给 RSU
    if (sm9_master_init() != APP_OK) return APP_ERR;
    uint8_t obu_prv[128]; uint32_t obu_prv_len = sizeof(obu_prv);
    if (sm9_issue_prv_for_id(obu_id, obu_prv, &obu_prv_len) != APP_OK) return APP_ERR;

    uint8_t sig[256]; uint32_t sig_len = sizeof(sig);
    if (sm9_sign(obu_id, obu_prv, obu_prv_len, ks->transcript, ks->transcript_len, sig, &sig_len) != APP_OK)
        return APP_ERR;

    if (net_send_packet(fd, MSG_AUTH_SIGNATURE, sig, sig_len) != APP_OK) return APP_ERR;

    // 5) 等待验签通过
    if (net_recv_packet(fd, &t, buf, &l, sizeof(buf)) != APP_OK || t != MSG_AUTH_VERIFY_OK) return APP_ERR;

    // 6) 生成最终会话密钥（此处先仅用 PQC；等你有 SM9 KDF 再混合）
    ks->k_final_len = sizeof(ks->k_final);
    if (scloud_mix_keys_sha256(NULL, 0, ks->k_pqc, ks->k_pqc_len, ks->k_final, &ks->k_final_len) != APP_OK)
        return APP_ERR;

    return APP_OK;
}
