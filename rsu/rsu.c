#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gmssl/sm9.h>
#include <gmssl/rand.h>

// ==== 配置 ====
#define SERVER_PORT 9000
#define BUFFER_SIZE 4096
#define ID_OBU "粤B12345"

// RSU 端的 SM9 签名主公钥（MPK）
SM9_SIGN_MASTER_KEY master_key;
SM9_SIGN_MASTER_PUBLIC_KEY master_pubkey;

// 从文件加载 SM9 主公钥
int load_master_pubkey(const char *file) {
    FILE *fp = fopen(file, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    if (sm9_sign_master_public_key_info_from_pem(&master_pubkey, fp) != 1) {
        fprintf(stderr, "加载SM9主公钥失败\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int main() {
    int listen_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // 1. 加载 SM9 主公钥（提前生成好）
    if (load_master_pubkey("sm9_master_pub.pem") != 0) {
        return -1;
    }
    printf("[RSU] 成功加载 SM9 主公钥\n");

    // 2. 创建 TCP 监听
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    printf("[RSU] 监听端口 %d...\n", SERVER_PORT);

    // 3. 等待 OBU 连接
    client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        return -1;
    }
    printf("[RSU] 接收到 OBU 连接: %s\n", inet_ntoa(client_addr.sin_addr));

    // 4. 接收 OBU 的认证请求
    int n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    buffer[n] = '\0';
    printf("[RSU] 收到认证请求: %s\n", buffer);

    // 5. 生成挑战 nonce
    unsigned char nonce[32];
    rand_bytes(nonce, sizeof(nonce));

    // 发送挑战给 OBU
    send(client_fd, nonce, sizeof(nonce), 0);
    printf("[RSU] 发送挑战 nonce\n");

    // 6. 接收 OBU 的签名
    unsigned char signature[SM9_SIGNATURE_SIZE];
    n = recv(client_fd, signature, sizeof(signature), 0);
    if (n != sizeof(signature)) {
        fprintf(stderr, "[RSU] 签名长度错误\n");
        close(client_fd);
        close(listen_fd);
        return -1;
    }

    // 构造 M = nonce || ID_OBU
    unsigned char message[64];
    size_t msglen = 0;
    memcpy(message, nonce, sizeof(nonce));
    msglen += sizeof(nonce);
    memcpy(message + msglen, ID_OBU, strlen(ID_OBU));
    msglen += strlen(ID_OBU);

    // 7. 验签
    if (sm9_verify(&master_pubkey, ID_OBU, strlen(ID_OBU),
                   message, msglen,
                   signature, sizeof(signature)) == 1) {
        printf("[RSU] 身份认证成功 ✅\n");
        const char *ok_msg = "auth_success";
        send(client_fd, ok_msg, strlen(ok_msg), 0);
    } else {
        printf("[RSU] 身份认证失败 ❌\n");
        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
