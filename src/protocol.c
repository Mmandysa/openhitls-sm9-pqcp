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
    printf("[RSU]send KEM public key\n");
    append_transcript(ks, rsu_pub, sc.pk_len);

    // 接收 OBU 的密文
    rc = net_recv_packet(fd, &t, buf, &l, sizeof(buf));
    printf("[RSU]net_recv_packet kem ciphertext: type=%u, len=%u\n", t, l);
    if (rc != APP_OK || t != MSG_KEM_CIPHERTEXT)
    {
        printf("net_recv_packet kem ciphertext failed\n");
        return APP_ERR;
    }
    printf("[RSU]recv KEM ciphertext\n");
    append_transcript(ks, buf, l);

    // 解封得到 k_pqc
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_rsu_decaps(&sc, rsu_prv, sc.sk_len, buf, l, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;
    printf("[RSU] decapsulation complete. Shared key length: %u\n", ks->k_pqc_len);
    //接受认证请求
    if (net_recv_packet(fd, &t, buf, &l, sizeof(buf)) != APP_OK || t != MSG_AUTH_REQUEST) 
    {
        printf("[RSU] 接收认证请求失败\n");
        return APP_ERR;
    }
    printf("[RSU] recv auth request, len=%u\n", l);
    append_transcript(ks, buf, l);

    cJSON *root = cJSON_Parse(buf);
    if (!root) { fprintf(stderr, "[RSU] JSON 解析失败\n"); return -1; }
    cJSON *id_item = cJSON_GetObjectItem(root, "id");
    if (!id_item || !cJSON_IsString(id_item)) { fprintf(stderr, "[RSU] JSON 中缺少 id\n"); cJSON_Delete(root);}
    const char *id = id_item->valuestring;
    printf("[RSU] OBU ID: %s\n", id);

    //生成nonce1
    uint8_t nonce1[32];
    RAND_bytes(nonce1, sizeof(nonce1));
    if(net_send_packet(fd, MSG_AUTH_RESPONSE, nonce1, sizeof(nonce1)) != APP_OK)
    {
        printf("[RSU] 发送 nonce1 失败\n");
        return APP_ERR;
    }
    printf("[RSU] send nonce1\n");
    for(int i=0;i<32;i++)
        printf("%02x",nonce1[i]);
    printf("\n");
    append_transcript(ks, nonce1, sizeof(nonce1));

    //接受签名
    uint8_t signature[MAX_PAYLOAD];
    if (net_recv_packet(fd, &t, signature, &l, sizeof(signature)) != APP_OK || t != MSG_AUTH_SIGNATURE) 
    {
        printf("[RSU] 接收签名失败\n");
        return APP_ERR;
    }
    printf("[RSU] recv signature, len=%u\n", l);
    append_transcript(ks, signature, l);
    printf("[RSU] 接收到的签名Hex (前20字节): ");
    for (int i = 0; i < (l < 20 ? l : 20); i++) {
        printf("%02X ", signature[i]);
    }
    printf("\n");


    // 验证签名
    size_t idlen = strlen(id);
    unsigned char *message = malloc(sizeof(nonce1) + idlen);
    if (!message) {fprintf(stderr, "malloc failed\n"); cJSON_Delete(root);}
    memcpy(message, nonce1, sizeof(nonce1));
    memcpy(message + sizeof(nonce1), id, idlen);
    size_t msglen = sizeof(nonce1) + idlen;

    SM9_SIGN_MASTER_KEY mpk;
    SM9_SIGN_CTX vctx;
    if(load_sm9_master_pub_key(&mpk) != 1) {
        fprintf(stderr, "[RSU] 加载 SM9 主公钥失败\n");
        free(message);
        return APP_ERR;
    }
    sm9_verify_init(&vctx);
    sm9_verify_update(&vctx, message, msglen);
    int ret = sm9_verify_finish(&vctx, signature, l, &mpk, id, idlen);
    free(message);
    if (ret == 1) {
        printf("[RSU] sm9 签名验证成功！\n");
    }

    //验证成功之后，发送nonce2
    unsigned char nonce2[32];
    RAND_bytes(nonce2, sizeof(nonce2));
    if(net_send_packet(fd, MSG_AUTH_VERIFY_OK, nonce2, sizeof(nonce2)) != APP_OK)
    {
        printf("[RSU] 发送 nonce2 失败\n");
        return APP_ERR;
    }
    printf("[RSU] send nonce2\n");
    append_transcript(ks, nonce2, sizeof(nonce2));

    scloud_mix_keys_sm3(ks);
    printf("[RSU] 会话密钥派生完成，k_final_len=%u\n", ks->k_final_len);

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
    if (net_recv_packet(fd, &t, buf, &l, sizeof(buf)) != APP_OK) 
    {
        printf("net_recv_packet kem public failed\n");
        return APP_ERR;
    }
    append_transcript(ks, buf, l);

    // 3) 封装得到密文和 k_pqc
    SCloudCtx sc = {0};
    uint8_t ct[20000] = {0}; uint32_t ct_len = sizeof(ct);
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_obu_encaps(&sc, buf, l, ct, &ct_len, ks->k_pqc, &ks->k_pqc_len) != APP_OK)
        return APP_ERR;

    // 发送密文
    if (net_send_packet(fd, MSG_KEM_CIPHERTEXT, ct, ct_len) != APP_OK) 
        return APP_ERR;
    append_transcript(ks, ct, ct_len);

    //加载 SM9 用户私钥
    SM9_SIGN_KEY msk;
    if(load_sm9_sign_key(&msk) != 1) return APP_ERR;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "id", obu_id);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) { fprintf(stderr, "[OBU] JSON 创建失败\n"); return -1; }

    //发送sm9认证请求
    if (net_send_packet(fd, MSG_AUTH_REQUEST, json_str, strlen(json_str)) != APP_OK) 
    {
        perror("[OBU] 发送认证请求失败");
        free(json_str);
        close(fd);
        return -1;
    }
    append_transcript(ks, json_str, strlen(json_str));
    free(json_str);

    //接收 nonce1 (32 bytes)
    uint8_t nonce1[32];

    if (net_recv_packet(fd, &t, nonce1, &l, sizeof(nonce1)) != APP_OK) 
    {
        perror("[OBU] 接收认证响应失败");
        close(fd);
        return -1;
    }
    for(int i=0;i<32;i++)
        printf("%02x",nonce1[i]);
    printf("\n");
    append_transcript(ks, nonce1, sizeof(nonce1));

    //构造M=nonce1||ID并签名
    size_t idlen = strlen(obu_id);
    unsigned char *message = malloc(32 + idlen);
    if (!message) 
    { 
        fprintf(stderr, "malloc fail\n");return -1; 
    }
    memcpy(message, nonce1, 32);
    memcpy(message + 32, obu_id, idlen);
    size_t msglen = 32 + idlen;

    SM9_SIGN_CTX sctx;
    unsigned char signature[SM9_SIGNATURE_SIZE];
    size_t siglen = sizeof(signature);

    sm9_sign_init(&sctx);
    sm9_sign_update(&sctx, message, msglen);
    if (sm9_sign_finish(&sctx, &msk, signature, &siglen) != 1) 
    {
        fprintf(stderr, "[OBU] 签名失败\n"); free(message); return -1;
    }
    printf("[OBU] 签名完成，长度: %zu\n", siglen);
    free(message);

    printf("[OBU] 即将发送的签名Hex (前20字节): ");
    for (int i = 0; i < (siglen < 20 ? siglen : 20); i++) {
        printf("%02X ", signature[i]);
    }
    printf("\n");
    //发送签名给 RSU
    if (net_send_packet(fd, MSG_AUTH_SIGNATURE, signature, siglen) != APP_OK) 
    {
        fprintf(stderr, "[OBU] 发送签名失败\n");
        close(fd);
        return -1;
    }
    append_transcript(ks, signature, siglen);

    //接收nonce2
    uint8_t nonce2[32];
    if (net_recv_packet(fd, &t, nonce2, &l, sizeof(nonce2)) != APP_OK || t != MSG_AUTH_VERIFY_OK) 
    {
        fprintf(stderr, "[OBU] 接收nonce2失败\n");
        close(fd);
        return -1;
    }
    append_transcript(ks, nonce2, sizeof(nonce2));

    scloud_mix_keys_sm3(ks);

    return APP_OK;
}
