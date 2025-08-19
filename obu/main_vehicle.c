// obu_gmssl.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>

#include <gmssl/sm9.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <openssl/rand.h>

#include "cjson/cJSON.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 8192

#define PASSWORD "obu_password"
#define OBU_ID "京A12345"

int load_sm9_sign_key(const char *file, SM9_SIGN_KEY *msk) {
    FILE *fp = fopen(file, "r");
    if (!fp) { perror("打开SM9私钥文件失败"); return 0; }
    if (sm9_sign_key_info_decrypt_from_pem(msk, PASSWORD, fp) != 1) {
        fprintf(stderr, "加载SM9私钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

// print hex helper
void print_hex(const char *title, const unsigned char *buf, size_t len) {
    printf("%s", title);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    SM9_SIGN_KEY msk;
    unsigned char recvbuf[BUFFER_SIZE];
    int n;

    if (!load_sm9_sign_key("sm9_user_sign_key.pem", &msk)) return -1;
    printf("[OBU] 成功加载 SM9 用户签名密钥\n");

    // 创建 TCP 连接
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { perror("connect"); close(sockfd); return -1; }
    printf("[OBU] 与服务器 %s:%d 建立 TCP 连接\n", SERVER_IP, SERVER_PORT);

    //===== 阶段1：sm9认证 =====
    // 1) 发送 JSON 认证请求 { "id": "..." }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "id", OBU_ID);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) { fprintf(stderr, "[OBU] JSON 创建失败\n"); close(sockfd); return -1; }
    if (send(sockfd, json_str, strlen(json_str), 0) != (ssize_t)strlen(json_str)) { perror("[OBU] 发送认证请求失败"); free(json_str); close(sockfd); return -1; }
    printf("[OBU] 发送认证请求: %s\n", json_str);
    free(json_str);

    // 2) 接收 nonce1 (32 bytes)
    n = recv(sockfd, recvbuf, 32, 0);
    if (n != 32) { fprintf(stderr, "[OBU] 接收 nonce1 失败或长度错误\n"); close(sockfd); return -1; }
    unsigned char nonce1[32];
    memcpy(nonce1, recvbuf, 32);
    printf("[OBU] 收到 nonce1\n");
    print_hex("[OBU] nonce1 = ", nonce1, sizeof(nonce1));

    // 3) 构造消息 M = nonce1 || ID 并签名
    size_t idlen = strlen(OBU_ID);
    unsigned char *message = malloc(32 + idlen);
    if (!message) { fprintf(stderr, "malloc fail\n"); close(sockfd); return -1; }
    memcpy(message, nonce1, 32);
    memcpy(message + 32, OBU_ID, idlen);
    size_t msglen = 32 + idlen;

    SM9_SIGN_CTX sctx;
    unsigned char signature[SM9_SIGNATURE_SIZE];
    size_t siglen = sizeof(signature);

    sm9_sign_init(&sctx);
    sm9_sign_update(&sctx, message, msglen);
    if (sm9_sign_finish(&sctx, &msk, signature, &siglen) != 1) {
        fprintf(stderr, "[OBU] 签名失败\n"); free(message); close(sockfd); return -1;
    }
    printf("[OBU] 签名完成，长度: %zu\n", siglen);
    print_hex("[OBU] signature = ", signature, siglen);

    free(message);

    // 4) 发送签名给 RSU
    if (send(sockfd, signature, siglen, 0) != (ssize_t)siglen) { perror("[OBU] 发送签名失败"); close(sockfd); return -1; }
    printf("[OBU] 签名发送成功\n");

    // 5) 接收 nonce2 (32 bytes) from RSU
    n = recv(sockfd, recvbuf, 32, 0);
    if (n != 32) { fprintf(stderr, "[OBU] 接收 nonce2 失败或长度错误\n"); close(sockfd); return -1; }
    unsigned char nonce2[32];
    memcpy(nonce2, recvbuf, 32);
    printf("[OBU] 收到 nonce2\n");
    print_hex("[OBU] nonce2 = ", nonce2, sizeof(nonce2));

    // 6) 派生会话密钥 K = SM3(nonce1 || nonce2 || id) -> 前16字节为 SM4 key
    unsigned char *kdf_in = malloc(32 + 32 + idlen);
    if (!kdf_in) { fprintf(stderr, "malloc fail\n"); close(sockfd); return -1; }
    size_t off = 0;
    memcpy(kdf_in + off, nonce1, 32); off += 32;
    memcpy(kdf_in + off, nonce2, 32); off += 32;
    memcpy(kdf_in + off, OBU_ID, idlen); off += idlen;

    unsigned char dgst[SM3_DIGEST_SIZE];
    SM3_CTX sm3ctx;
    sm3_init(&sm3ctx);
    sm3_update(&sm3ctx, kdf_in, off);
    sm3_finish(&sm3ctx, dgst);

    free(kdf_in);

    unsigned char sm4_key[16];
    memcpy(sm4_key, dgst, 16);
    print_hex("[OBU] 派生会话密钥 K = ", sm4_key, 16);

    // 7) 使用 SM4-CBC 加密一条消息并发送给 RSU
    const char *plain_text = "Hello RSU, this is OBU!";
    size_t pt_len = strlen(plain_text);
    int block = 16;
    int pad = block - (pt_len % block);
    size_t padded_len = pt_len + pad;
    unsigned char *padded = malloc(padded_len);
    memcpy(padded, plain_text, pt_len);
    for (size_t i = pt_len; i < padded_len; i++) padded[i] = (unsigned char)pad;

    // 生成 IV
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    print_hex("[OBU] IV = ", iv, sizeof(iv));

    // SM4-CBC 加密（使用 sm4_set_encrypt_key + sm4_encrypt）
    SM4_KEY sm4_enc_key;
    sm4_set_encrypt_key(&sm4_enc_key, sm4_key);

    unsigned char *ciphertext = malloc(padded_len);
    unsigned char prev_iv[16];
    memcpy(prev_iv, iv, 16);

    for (size_t offb = 0; offb < padded_len; offb += 16) {
        unsigned char xored[16];
        for (int i = 0; i < 16; i++) xored[i] = padded[offb + i] ^ prev_iv[i];
        unsigned char outblock[16];
        sm4_encrypt(&sm4_enc_key, xored, outblock);
        memcpy(ciphertext + offb, outblock, 16);
        memcpy(prev_iv, outblock, 16);
    }

    // 发送格式：[4 bytes ciphertext_len network order][16 bytes IV][ciphertext]
    uint32_t net_len = htonl((uint32_t)padded_len);
    if (send(sockfd, &net_len, sizeof(net_len), 0) != sizeof(net_len)) { perror("[OBU] 发送长度失败"); free(padded); free(ciphertext); close(sockfd); return -1; }
    if (send(sockfd, iv, sizeof(iv), 0) != sizeof(iv)) { perror("[OBU] 发送 IV 失败"); free(padded); free(ciphertext); close(sockfd); return -1; }

    size_t sent = 0;
    while (sent < padded_len) {
        n = send(sockfd, ciphertext + sent, padded_len - sent, 0);
        if (n <= 0) { perror("[OBU] 发送 ciphertext 失败"); free(padded); free(ciphertext); close(sockfd); return -1; }
        sent += n;
    }
    printf("[OBU] 已发送加密消息 (cipher_len=%zu)\n", padded_len);
    print_hex("[OBU] Ciphertext = ", ciphertext, padded_len);

    free(padded);
    free(ciphertext);
    close(sockfd);
    return 0;
}
