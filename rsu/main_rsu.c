// rsu_gmssl.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdint.h>

#include <gmssl/sm9.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

#include <openssl/rand.h>

#include "crypt_eal_rand.h"
#include "cjson/cJSON.h"

#define LISTEN_PORT 12345
#define BACKLOG 5
#define BUFFER_SIZE 8192

// 加载 SM9 主公钥
int load_sm9_master_pubkey(const char *file, SM9_SIGN_MASTER_KEY *mpk) {
    FILE *fp = fopen(file, "r");
    if (!fp) { perror("打开SM9公钥文件失败"); return 0; }
    if (sm9_sign_master_public_key_from_pem(mpk, fp) != 1) {
        fprintf(stderr, "读取SM9主公钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

// 打印十六进制字符串
void print_hex(const char *title, const unsigned char *buf, size_t len) {
    printf("%s", title);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    SM9_SIGN_MASTER_KEY mpk;
    char buffer[BUFFER_SIZE];

    // 加载 SM9 主公钥
    if (!load_sm9_master_pubkey("sm9_sign_master_public.pem", &mpk)) {
        return -1;
    }
    printf("[RSU] 成功加载 SM9 主公钥\n");

    // 监听端口
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(LISTEN_PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind"); close(listenfd); return -1;
    }
    if (listen(listenfd, BACKLOG) < 0) { perror("listen"); close(listenfd); return -1; }
    printf("[RSU] 监听端口 %d, 等待连接...\n", LISTEN_PORT);

    // 接受连接
    int connfd = accept(listenfd, NULL, NULL);
    if (connfd < 0) { perror("accept"); close(listenfd); return -1; }


    // ====== 阶段1：sm9 认证 ======
    // 1) 接收 OBU 的认证请求 JSON (包含 id)
    int n = recv(connfd, buffer, BUFFER_SIZE - 1, 0);
    if (n <= 0) { perror("[RSU] recv"); close(connfd); close(listenfd); return -1; }
    buffer[n] = '\0';
    printf("[RSU] 收到认证请求: %s\n", buffer);

    cJSON *root = cJSON_Parse(buffer);
    if (!root) { fprintf(stderr, "[RSU] JSON 解析失败\n"); close(connfd); close(listenfd); return -1; }
    cJSON *id_item = cJSON_GetObjectItem(root, "id");
    if (!id_item || !cJSON_IsString(id_item)) { fprintf(stderr, "[RSU] JSON 中缺少 id\n"); cJSON_Delete(root); goto fail; }
    const char *id = id_item->valuestring;
    printf("[RSU] OBU ID: %s\n", id);

    // 2) RSU 生成 nonce1，通过challenge确保连接有效，防止重放攻击
    unsigned char nonce1[32];
    RAND_bytes(nonce1, sizeof(nonce1));

    // 将 nonce1 发给 OBU
    if (send(connfd, nonce1, sizeof(nonce1), 0) != sizeof(nonce1)) {
        perror("[RSU] 发送 nonce1 失败");
        cJSON_Delete(root);
        goto fail;
    }
    printf("[RSU] 发送挑战 nonce1\n");
    print_hex("[RSU] nonce1 = ", nonce1, sizeof(nonce1));

    // 3) 接收 OBU 签名 (SM9 signature)
    unsigned char signature[SM9_SIGNATURE_SIZE];
    n = recv(connfd, signature, sizeof(signature), 0);
    if (n <= 0) { perror("[RSU] recv signature"); cJSON_Delete(root); goto fail; }
    size_t siglen = n;
    printf("[RSU] 收到签名，长度: %zu\n", siglen);

    // 4) 验签：消息 M = nonce1 || ID
    size_t idlen = strlen(id);
    unsigned char *message = malloc(sizeof(nonce1) + idlen);
    if (!message) { fprintf(stderr, "malloc failed\n"); cJSON_Delete(root); goto fail; }
    memcpy(message, nonce1, sizeof(nonce1));
    memcpy(message + sizeof(nonce1), id, idlen);
    size_t msglen = sizeof(nonce1) + idlen;

    SM9_SIGN_CTX vctx;
    sm9_verify_init(&vctx);
    sm9_verify_update(&vctx, message, msglen);
    int ret = sm9_verify_finish(&vctx, signature, siglen, &mpk, id, idlen);
    free(message);

    if (ret == 1) {
        printf("[RSU] sm9 签名验证成功！\n");
    } else {
        printf("[RSU] sm9 签名验证失败！\n");
        cJSON_Delete(root);
        goto fail;
    }

    // ====== 阶段2：派生会话密钥 K  ======
    // RSU 生成 nonce2 并发送给 OBU，双方用 K = SM3(nonce1 || nonce2 || id) -> 取前16字节作为 SM4 key
    unsigned char nonce2[32];
    RAND_bytes(nonce2, sizeof(nonce2));

    if (send(connfd, nonce2, sizeof(nonce2), 0) != sizeof(nonce2)) {
        perror("[RSU] 发送 nonce2 失败");
        cJSON_Delete(root);
        goto fail;
    }
    printf("[RSU] 发送 nonce2\n");
    print_hex("[RSU] nonce2 = ", nonce2, sizeof(nonce2));

    // 派生 K：SM3(nonce1 || nonce2 || id)
    unsigned char *kdf_in = malloc(sizeof(nonce1) + sizeof(nonce2) + idlen);
    if (!kdf_in) { fprintf(stderr, "malloc fail\n"); cJSON_Delete(root); goto fail; }
    size_t off = 0;
    memcpy(kdf_in + off, nonce1, sizeof(nonce1)); off += sizeof(nonce1);
    memcpy(kdf_in + off, nonce2, sizeof(nonce2)); off += sizeof(nonce2);
    memcpy(kdf_in + off, id, idlen); off += idlen;

    unsigned char dgst[SM3_DIGEST_SIZE];
    SM3_CTX sm3ctx;
    sm3_init(&sm3ctx);
    sm3_update(&sm3ctx, kdf_in, off);
    sm3_finish(&sm3ctx, dgst);

    free(kdf_in);

    // 会话密钥取 dgst[0..15]
    unsigned char sm4_key[16];
    memcpy(sm4_key, dgst, 16);
    print_hex("[RSU] 派生会话密钥 K = ", sm4_key, 16);

    // 发送确认信息给 OBU（可选），然后等待 OBU 发来加密消息
    // 这里直接接收：格式 [4 bytes ciphertext_len network order][16 bytes IV][ciphertext]
    uint32_t net_len;
    n = recv(connfd, &net_len, sizeof(net_len), 0);
    if (n != sizeof(net_len)) { fprintf(stderr, "[RSU] 未收到加密消息长度\n"); cJSON_Delete(root); goto fail; }
    uint32_t ciphertext_len = ntohl(net_len);
    if (ciphertext_len == 0 || ciphertext_len > BUFFER_SIZE) { fprintf(stderr, "[RSU] 非法的密文长度: %u\n", ciphertext_len); cJSON_Delete(root); goto fail; }

    unsigned char iv[16];
    n = recv(connfd, iv, sizeof(iv), 0);
    if (n != sizeof(iv)) { fprintf(stderr, "[RSU] 接收 IV 失败\n"); cJSON_Delete(root); goto fail; }

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) { fprintf(stderr, "malloc fail\n"); cJSON_Delete(root); goto fail; }
    size_t recvd = 0;
    while (recvd < ciphertext_len) {
        n = recv(connfd, ciphertext + recvd, ciphertext_len - recvd, 0);
        if (n <= 0) { perror("[RSU] recv ciphertext"); free(ciphertext); cJSON_Delete(root); goto fail; }
        recvd += n;
    }
    printf("[RSU] 接收到加密消息 (len=%u)\n", ciphertext_len);
    print_hex("[RSU] Ciphertext = ", ciphertext, ciphertext_len);

    // SM4-CBC 解密
    SM4_KEY sm4_dec_key;
    sm4_set_decrypt_key(&sm4_dec_key, sm4_key);

    if (ciphertext_len % 16 != 0) { fprintf(stderr, "[RSU] 密文长度不是16字节整数倍\n"); free(ciphertext); cJSON_Delete(root); goto fail; }
    unsigned char prev_iv[16];
    memcpy(prev_iv, iv, 16);
    unsigned char *plain = malloc(ciphertext_len);
    if (!plain) { free(ciphertext); cJSON_Delete(root); goto fail; }

    for (size_t offb = 0; offb < ciphertext_len; offb += 16) {
        unsigned char outblock[16];
        // 用解密轮的 key 调用 sm4_encrypt（头文件风格）
        sm4_encrypt(&sm4_dec_key, ciphertext + offb, outblock);
        for (int i = 0; i < 16; i++) {
            plain[offb + i] = outblock[i] ^ prev_iv[i];
        }
        memcpy(prev_iv, ciphertext + offb, 16);
    }

    int pad = plain[ciphertext_len - 1];
    if (pad <= 0 || pad > 16) pad = 0;
    size_t plain_len = (pad > 0 ? ciphertext_len - pad : ciphertext_len);

    printf("[RSU] 解密后明文 (len=%zu):\n", plain_len);
    fwrite(plain, 1, plain_len, stdout);
    printf("\n");

    free(plain);
    free(ciphertext);
    cJSON_Delete(root);
    close(connfd);
    close(listenfd);
    return 0;

fail:
    perror("[RSU] 失败");
    close(connfd);
    close(listenfd);
    return -1;
}
