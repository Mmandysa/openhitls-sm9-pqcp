#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"
#include "common.h"
#define MAX_PAYLOAD_SIZE 1024
void test_basic_packet(int fd) {
    // 测试1: 发送普通数据包
    const char *message = "";
    if (net_send_packet(fd, MSG_KEM_PUBKEY , message, strlen(message)) != APP_OK) {
        printf("Failed to send basic packet\n");
        return;
    }
    printf("Sent basic packet\n");
    
    // 接收响应
    uint16_t type;
    uint32_t len;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    
    if (net_recv_packet(fd, &type, payload, &len, MAX_PAYLOAD_SIZE) != APP_OK) {
        printf("Failed to receive response packet\n");
        return;
    }
    printf("Received response - Type: 0x%04X, Length: %u, Content: %.*s\n", 
           type, len, (int)len, payload);
}

void test_empty_payload(int fd) {
    // 测试2: 发送空负载包
    if (net_send_packet(fd, 0x0002, NULL, 0) != APP_OK) {
        printf("Failed to send empty payload packet\n");
        return;
    }
    printf("Sent empty payload packet\n");
}

void test_large_payload(int fd) {
    // 测试3: 接收大负载包
    uint16_t type;
    uint32_t len;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    
    if (net_recv_packet(fd, &type, payload, &len, MAX_PAYLOAD_SIZE) != APP_OK) {
        printf("Failed to receive large payload packet\n");
        return;
    }
    printf("Received large payload - Type: 0x%04X, Length: %u\n", type, len);
    
    // 验证内容 (前10字节和后10字节)
    printf("First 10 bytes: %.10s\n", payload);
    printf("Last 10 bytes: %.10s\n", payload + len - 10);
}

void test_termination(int fd) {
    // 测试4: 发送终止包
    if (net_send_packet(fd, 0xFFFF, NULL, 0) != APP_OK) {
        printf("Failed to send termination packet\n");
        return;
    }
    printf("Sent termination packet\n");
}
int main(int argc, char *argv[]) {
    int fd = net_connect("127.0.0.1", 12345);
    if (fd < 0) {
        perror("Failed to connect");
        return -1;
    }
    
    char msg[] = "Hello, server!";
    uint32_t msg_len = strlen(msg); // 不包含终止符
    uint32_t net_len = htonl(msg_len);
    
    // 先发送长度
    if (net_send_all(fd, &net_len, sizeof(net_len)) < 0) {
        perror("Failed to send length");
        net_close(fd);
        return -1;
    }
    
    // 再发送消息
    if (net_send_all(fd, msg, msg_len) < 0) {
        perror("Failed to send message");
        net_close(fd);
        return -1;
    }
    printf("Sent: %s (length: %u)\n", msg, msg_len);
    
    // 接收响应长度
    uint32_t resp_len;
    if (net_recv_all(fd, &resp_len, sizeof(resp_len)) < 0) {
        perror("Failed to receive response length");
        net_close(fd);
        return -1;
    }
    resp_len = ntohl(resp_len);
    
    // 接收响应内容
    char buf[1024];
    if (resp_len >= sizeof(buf)) {
        fprintf(stderr, "Response too long\n");
        net_close(fd);
        return -1;
    }
    
    if (net_recv_all(fd, buf, resp_len) < 0) {
        perror("Failed to receive response");
        net_close(fd);
        return -1;
    }
    printf("Received response: %s (length: %u)\n", buf, resp_len);
    test_basic_packet(fd);
    test_basic_packet(fd);
    
    net_close(fd);
    return 0;
}