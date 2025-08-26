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

int protocol_rsu_handshake(int fd, const char *expected_obu_sign_id, const char *expected_obu_exch_id, const char *rsu_exch_id, SessionKeys *ks) {
    int ret;
    uint16_t type;
    uint32_t length;
    uint8_t buf[MAX_PAYLOAD];

    //========== 阶段1：接收ClientHello，完成SM9认证 和 SM9密钥交换 ==========
    ret = net_recv_packet(fd, &type, buf, &length, sizeof(buf));
    if (ret != APP_OK || type != MSG_HELLO) return APP_ERR;
    append_transcript(ks, buf, length);

    // 1. 加载签名验证所需的主公钥
    SM9_SIGN_MASTER_KEY sign_mpk;
    if(!load_sm9_master_pub_key(&sign_mpk)) return APP_ERR;

    // 2. 加载KEX所需的密钥
    SM9_ENC_MASTER_KEY enc_mpk;
    if (!load_sm9_enc_master_pub_key(&enc_mpk)) return APP_ERR;
    
    // 调用为RSU专设的加载函数
    SM9_ENC_KEY rsu_exch_key;
    if (!load_sm9_enc_key(&rsu_exch_key, RSU_ENC_KEY_PATH)) return APP_ERR;

    // 3. 解析并验证ClientHello
    SM9_Z256_POINT RA;
    char parsed_obu_sign_id[20] = {0}; // 增加缓冲区大小以防万一
    char parsed_obu_exch_id[20] = {0};
    if(parse_message_hello(buf, length, parsed_obu_sign_id, parsed_obu_exch_id, &sign_mpk, &RA) != APP_OK) {
        fprintf(stderr, "[RSU] 解析或验证ClientHello失败\n");
        return APP_ERR;
    }
    printf("[RSU] ClientHello signature verified. RA parsed.\n");

    // 校验解析出的ID是否是期望的ID
    if (strcmp(parsed_obu_sign_id, expected_obu_sign_id) != 0 || strcmp(parsed_obu_exch_id, expected_obu_exch_id) != 0) {
        fprintf(stderr, "[RSU] ERROR: OBU ID mismatch!\n");
        return APP_ERR;
    }
    
    // 5. [KEX] 使用解析出的 交换ID (parsed_obu_exch_id) 进行计算
    SM9_Z256_POINT RB;
    if (sm9_kex_rsu_respond(ks, &enc_mpk, &rsu_exch_key, parsed_obu_exch_id, rsu_exch_id, &RA, &RB) != APP_OK) {
        fprintf(stderr, "[RSU] SM9 KEX respond failed.\n");
        return APP_ERR;
    }

    //============ 阶段2：PQC KEX 并发送响应 ============
    SCloudCtx sc = {0};
    uint8_t rsu_pub[20000] = {0}, rsu_prv[20000] = {0};
    uint32_t pub_len = sizeof(rsu_pub), prv_len = sizeof(rsu_prv);
    if (scloud_rsu_keygen(&sc, SCLOUDPLUS_SECBITS1, rsu_pub, pub_len, rsu_prv, prv_len) != APP_OK) return APP_ERR;

    // 构造Server Response = RB || PQC公钥
    uint8_t rb_buf[65];
    sm9_z256_point_to_uncompressed_octets(&RB, rb_buf);
    uint8_t server_response[MAX_PAYLOAD];
    memcpy(server_response, rb_buf, 65);
    memcpy(server_response + 65, rsu_pub, sc.pk_len);
    uint32_t response_len = 65 + sc.pk_len;
    
    if (net_send_packet(fd, MSG_KEM_PUBKEY, server_response, response_len) != APP_OK) return APP_ERR;
    printf("[RSU] Sent Server Response (RB + PQC Public Key)\n");
    append_transcript(ks, server_response, response_len);

    // 接收OBU的PQC密文
    ret = net_recv_packet(fd, &type, buf, &length, sizeof(buf));
    if (ret != APP_OK || type != MSG_KEM_CIPHERTEXT) return APP_ERR;
    append_transcript(ks, buf, length);

    // 解封得到k_pqc
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_rsu_decaps(&sc, rsu_prv, sc.sk_len, buf, length, ks->k_pqc, &ks->k_pqc_len) != APP_OK) return APP_ERR;
    printf("[RSU] k_pqc decapsulated. Length: %u\n", ks->k_pqc_len);

    //============ 阶段3：生成最终会话密钥 ============
    scloud_mix_keys_sm3(ks);
    printf("[RSU] Handshake complete. Final key generated.\n");

    return APP_OK;
}


int protocol_obu_handshake(int fd, const char *sign_id, const char *exch_id, const char *rsu_exch_id, SessionKeys *ks) {
    uint16_t type;
    uint32_t length;
    uint8_t buf[MAX_PAYLOAD];

    //================= 阶段1：SM9 KEX 发起 与 认证 =================
    // 1. 加载OBU的签名私钥
    SM9_SIGN_KEY sign_key;
    if(!load_sm9_sign_key(&sign_key)) return APP_ERR;

    // 2. 加载KEX所需的密钥
    // *** 关键修改 *** 调用为OBU专设的加载函数
    SM9_ENC_KEY exch_key;
    if (!load_sm9_enc_key(&exch_key, OBU_ENC_KEY_PATH)) return APP_ERR;

    SM9_ENC_MASTER_KEY enc_mpk;
    if (!load_sm9_enc_master_pub_key(&enc_mpk)) return APP_ERR;

    // 3. [KEX] 使用rsu的交换ID(rsu_exch_id) 发起密钥交换
    SM9_Z256_POINT RA;
    if (sm9_kex_obu_start(ks, &enc_mpk, rsu_exch_id, &RA) != APP_OK) return APP_ERR;
    
    // +++ 在这里添加 RA 的打印代码 +++
    // +++ 新增开始 +++
    uint8_t ra_buf_print[65];
    sm9_z256_point_to_uncompressed_octets(&RA, ra_buf_print);
    printf("--- [OBU DEBUG] ---\n");
    printf("Generated RA: ");
    for (int i = 0; i < 65; i++) {
        printf("%02x", ra_buf_print[i]);
    }
    printf("\n---------------------\n");
    // +++ 新增结束 +++

    // 4. 构造并发送ClientHello，同时包含 *签名ID* 和 *交换ID*
    if(generate_message_hello(buf, &length, sign_id, exch_id, &sign_key, &RA) != APP_OK) return APP_ERR;
    
    if(net_send_packet(fd, MSG_HELLO, buf, length) != APP_OK) return APP_ERR;
    append_transcript(ks, buf, length);
    printf("[OBU] ClientHello sent.\n");

    //======= 阶段2：接收RSU响应，完成SM9 KEX 和 SCloud+ KEX =======
    if (net_recv_packet(fd, &type, buf, &length, sizeof(buf)) != APP_OK) return APP_ERR;
    append_transcript(ks, buf, length);

    // 解析Server Response
    if (length < 65) return APP_ERR;
    uint8_t *rb_buf = buf;
    uint8_t *rsu_pqc_pub = buf + 65;
    uint32_t rsu_pqc_pub_len = length - 65;

    SM9_Z256_POINT RB;
    if (sm9_z256_point_from_uncompressed_octets(&RB, rb_buf) != 1) return APP_ERR;
    
    // +++ 在这里添加 RB 的打印代码 +++
    // +++ 新增开始 +++
    printf("--- [OBU DEBUG] ---\n");
    printf("Received  RB: ");
    for (int i = 0; i < 65; i++) {
        // rb_buf 就是RB的字节串，可以直接使用
        printf("%02x", rb_buf[i]);
    }
    printf("\n---------------------\n");
    // +++ 新增结束 +++
    
    // 1. [KEX] 使用自己的 *交换ID* (exch_id) 完成k_sm9的计算
    if (sm9_kex_obu_finish(ks, &enc_mpk, &exch_key, exch_id, rsu_exch_id, &RA, &RB) != APP_OK) return APP_ERR;

    // 2. [PQC KEX] 封装得到k_pqc
    SCloudCtx sc = {0};
    uint8_t ct[20000] = {0}; uint32_t ct_len = sizeof(ct);
    ks->k_pqc_len = sizeof(ks->k_pqc);
    if (scloud_obu_encaps(&sc, rsu_pqc_pub, rsu_pqc_pub_len, ct, &ct_len, ks->k_pqc, &ks->k_pqc_len) != APP_OK) return APP_ERR;

    // 发送PQC密文
    if (net_send_packet(fd, MSG_KEM_CIPHERTEXT, ct, ct_len) != APP_OK) return APP_ERR;
    append_transcript(ks, ct, ct_len);
    printf("[OBU] PQC ciphertext sent. k_pqc length: %u\n", ks->k_pqc_len);

    //============== 阶段3：生成最终会话密钥 ===============
    scloud_mix_keys_sm3(ks);
    printf("[OBU] Handshake complete. Final key generated.\n");

    return APP_OK;
}