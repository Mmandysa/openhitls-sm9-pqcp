#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pqcp.h"  // openHiTLS PQCP 头文件，确保你的库路径正确

#define PORT 12345
#define BUFFER_SIZE 4096

int main() {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listenfd); return -1;
    }
    if (listen(listenfd, 1) < 0) {
        perror("listen"); close(listenfd); return -1;
    }
    printf("[Server] Listening on port %d...\n", PORT);

    int connfd = accept(listenfd, NULL, NULL);
    if (connfd < 0) { perror("accept"); close(listenfd); return -1; }
    printf("[Server] Client connected\n");

    // 1. 初始化 KEM 算法 ctx
    pqcp_ctx_t *ctx = NULL;
    if (pqcp_ctx_init(&ctx, PQCP_ALG_KEM_SCLOUDPLUS, PQCP_MODE_KEM_ENCAP) != PQCP_SUCCESS) {
        fprintf(stderr, "[Server] pqcp_ctx_init failed\n");
        close(connfd); close(listenfd); return -1;
    }

    // 2. 生成密钥对
    uint8_t pk[256] = {0};  // 公钥缓冲
    uint8_t sk[512] = {0};  // 私钥缓冲
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);
    if (pqcp_kem_keygen(ctx, pk, &pk_len, sk, &sk_len) != PQCP_SUCCESS) {
        fprintf(stderr, "[Server] pqcp_kem_keygen failed\n");
        pqcp_ctx_free(ctx);
        close(connfd); close(listenfd); return -1;
    }
    printf("[Server] KEM keypair generated, pk_len=%zu, sk_len=%zu\n", pk_len, sk_len);

    // 3. 发送公钥给客户端
    if (send(connfd, &pk_len, sizeof(pk_len), 0) != sizeof(pk_len) ||
        send(connfd, pk, pk_len, 0) != (ssize_t)pk_len) {
        perror("[Server] send public key failed");
        pqcp_ctx_free(ctx);
        close(connfd); close(listenfd); return -1;
    }
    printf("[Server] Sent public key to client\n");

    // 4. 接收客户端封装的密文
    size_t ct_len = 0;
    if (recv(connfd, &ct_len, sizeof(ct_len), 0) != sizeof(ct_len) || ct_len == 0 || ct_len > BUFFER_SIZE) {
        fprintf(stderr, "[Server] Invalid ciphertext length\n");
        pqcp_ctx_free(ctx);
        close(connfd); close(listenfd); return -1;
    }
    uint8_t ct[BUFFER_SIZE] = {0};
    size_t recvd = 0;
    while (recvd < ct_len) {
        ssize_t n = recv(connfd, ct + recvd, ct_len - recvd, 0);
        if (n <= 0) { perror("[Server] recv ciphertext failed"); break; }
        recvd += n;
    }
    if (recvd != ct_len) {
        fprintf(stderr, "[Server] Ciphertext receive incomplete\n");
        pqcp_ctx_free(ctx);
        close(connfd); close(listenfd); return -1;
    }
    printf("[Server] Received ciphertext from client\n");

    // 5. 解封密钥
    uint8_t shared_key[64] = {0};
    size_t shared_key_len = sizeof(shared_key);
    if (pqcp_kem_decaps(ctx, shared_key, &shared_key_len, ct, ct_len, sk, sk_len) != PQCP_SUCCESS) {
        fprintf(stderr, "[Server] pqcp_kem_decaps failed\n");
        pqcp_ctx_free(ctx);
        close(connfd); close(listenfd); return -1;
    }

    printf("[Server] Shared key derived (length=%zu): ", shared_key_len);
    for (size_t i = 0; i < shared_key_len; i++) printf("%02x", shared_key[i]);
    printf("\n");

    // 6. 清理资源
    pqcp_ctx_free(ctx);
    close(connfd);
    close(listenfd);
    return 0;
}
