#include<stdio.h>
#include<string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define password "obu_password"

int load_sm9_sign_key(const char *file, SM9_SIGN_KEY *msk) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("打开SM9私钥文件失败");
        return 0;
    }
    // 从 PEM 文件加载密钥
    if (sm9_sign_key_info_decrypt_from_pem(msk, password, fp) != 1) {
        fprintf(stderr, "加载SM9私钥失败\n"); 
    }
    fclose(fp);
    return 1;
}

int main() {
    SM9_SIGN_KEY msk;
    if (!load_sm9_sign_key("sm9_user_sign_key.pem", &msk)) {
        return -1;
    }

    const char *id = "京A12345";

    uint8_t signature[256];
    size_t siglen = sizeof(signature);

    // 签名
    SM9_SIGN_CTX ctx;sm9_sign_init(&ctx);
    if (!(sm9_sign_update(&ctx, (const uint8_t *)id, strlen(id))&&sm9_sign_finish(&ctx, &msk, signature, &siglen))) {
        fprintf(stderr, "SM9签名失败\n");
        return -1;
    }

    // 建立TCP连接发送数据
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); //tcp流式套接字
    if (!sockfd) { perror("socket"); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    // 发送ID长度+ID
    uint32_t id_len = htonl(strlen(id));
    if (write(sockfd, &id_len, sizeof(id_len)) < 0) goto fail;
    if (write(sockfd, id, strlen(id)) < 0) goto fail;

    // 发送签名长度+签名
    uint32_t sig_len_net = htonl(siglen);
    if (write(sockfd, &sig_len_net, sizeof(sig_len_net)) < 0) goto fail;
    if (write(sockfd, signature, siglen) < 0) goto fail;

    printf("身份请求发送成功\n");
    close(sockfd);
    return 0;

fail:
    perror("发送失败");
    close(sockfd);
    return -1;
}
