#include "protocol.h"
#include "net.h"
#include "scloud_kem.h"
#include "sm9_utils.h"
#include "cjson/cJSON.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/rand.h>

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
    int ret;    // 返回值
    uint16_t type; // 消息类型
    uint32_t length; //消息有效载荷长度
    uint8_t buf[MAX_PAYLOAD]; //缓冲区

    //==========阶段1：进行sm9认证===========
    ret = net_recv_packet(fd, &type, buf, &length, sizeof(buf));
    if (ret != APP_OK || type != MSG_HELLO) return APP_ERR;
    append_transcript(ks, &buf, length);
    SM9_SIGN_MASTER_KEY mpk;
    if(load_sm9_master_pub_key(&mpk) != 1) {
        fprintf(stderr, "[RSU] 加载 SM9 主公钥失败\n");
        return APP_ERR;
    }
    char id[10] = {0};
    if(parse_message_hello(buf, length,id, &mpk) != APP_OK) {
        fprintf(stderr, "[RSU] 解析 HELLO 消息失败\n");
        return APP_ERR;
    }
    printf("[OK] SM9 verification succeeded\n");

    //============阶段2：生成 SCloud+ 秘钥k_pqc============
    // 1.生成 SCloud+ 密钥对
    SCloudCtx sc = {0};
    uint8_t rsu_pub[20000] = {0}, rsu_prv[20000] = {0};
    uint32_t pub_len = sizeof(rsu_pub), prv_len = sizeof(rsu_prv);

    if (scloud_rsu_keygen(&sc, SCLOUDPLUS_SECBITS1, rsu_pub, pub_len, rsu_prv, prv_len) != APP_OK)      
    {
        printf("scloud_rsu_keygen failed\n");
        return APP_ERR;
    }

    // 2.发送 KEM 公钥
    if (net_send_packet(fd, MSG_KEM_PUBKEY, rsu_pub, sc.pk_len) != APP_OK) 
    {
        printf("net_send_packet kem public failed\n");
        return APP_ERR;
    }
    printf("[RSU]send KEM public key\n");
    append_transcript(ks, rsu_pub, sc.pk_len);

    // 3.接收 OBU 的密文
    ret = net_recv_packet(fd, &type, buf, &length, sizeof(buf));
    printf("[RSU]net_recv_packet kem ciphertext: type=%u, len=%u\n", type, length);
    if (ret != APP_OK || type != MSG_KEM_CIPHERTEXT)
    {
        printf("net_recv_packet kem ciphertext failed\n");
        return APP_ERR;
    }
    printf("[RSU]recv KEM ciphertext\n");
    append_transcript(ks, buf, length);

    // 4.解封得到 k_pqc
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_rsu_decaps(&sc, rsu_prv, sc.sk_len, buf, length, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;
    printf("[RSU] decapsulation complete. Shared key length: %u\n", ks->k_pqc_len);
    printf("[RSU]k_pqc: ");
    for(int i = 0; i < ks->k_pqc_len; i++) {
        printf("%02x", ks->k_pqc[i]);
    }
    printf("\n");

    //========阶段3：生成会话密钥========
    scloud_mix_keys_sm3(ks);
    printf("[RSU] 会话密钥派生完成，k_final_len=%u\n", ks->k_final_len);

    return APP_OK;
}

int protocol_obu_handshake(int fd, const char *obu_id, SessionKeys *ks) {
    uint16_t type; //消息类型
    uint32_t length; //消息有效载荷长度
    uint8_t buf[MAX_PAYLOAD];//缓冲区

    //=================阶段1：进行sm9认证================    
    // 1) 发送 HELLO
    
    SM9_SIGN_KEY user_key;
    if(load_sm9_sign_key(&user_key) != 1) 
    {
        printf("[ER] load_sm9_sign_key failed\n");
        return APP_ERR;
    }
    if(generate_message_hello(buf, &length, obu_id, &user_key) != APP_OK)
    {
        printf("[ER] generate_message_hello failed\n");
        return APP_ERR;
    }
    for(int i = 32; i < 40; i++)
    {
        printf("%c", buf[i]);
    }
    if(net_send_packet(fd, MSG_HELLO, buf, length) != APP_OK)
    {
        printf("[ER] net_send_hello_packet failed\n");
        return APP_ERR;
    }
    append_transcript(ks, buf, length);
    printf("[OK] net_send_hello_packet succeeded\n");



    //=======阶段2：生成 SCloud+ 密钥k_pqc=======
    //1.接收RSU公钥
    if (net_recv_packet(fd, &type, buf, &length, sizeof(buf)) != APP_OK) 
    {
        printf("net_recv_packet kem public failed\n");
        return APP_ERR;
    }
    append_transcript(ks, buf, length);
    // 1.封装得到密文和 k_pqc
    SCloudCtx sc = {0};
    uint8_t ct[20000] = {0}; uint32_t ct_len = sizeof(ct);
    ks->k_pqc_len = sizeof(ks->k_pqc);
    // int scloud_obu_encaps(SCloudCtx *sc, const uint8_t *rsu_pub, uint32_t rsu_pub_len,
    //                   uint8_t *cipher, uint32_t *cipher_len,
    //                   uint8_t *k_pqc, uint32_t *k_pqc_len)
    if (scloud_obu_encaps(&sc, buf, length, ct, &ct_len, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;

    // 2.发送密文
    if (net_send_packet(fd, MSG_KEM_CIPHERTEXT, ct, ct_len) != APP_OK) 
        return APP_ERR;
    append_transcript(ks, ct, ct_len);
    printf("[OBU]k_pqc: ");
    for(int i = 0; i < ks->k_pqc_len; i++) {
        printf("%02x", ks->k_pqc[i]);
    }
    printf("\n");

    //==============阶段3：生成会话密钥===============
    scloud_mix_keys_sm3(ks);

    printf("[OBU] 会话密钥派生完成，k_final_len=%u\n", ks->k_final_len);

    return APP_OK;
}
