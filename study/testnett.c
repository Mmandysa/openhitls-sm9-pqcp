#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"
#include "common.h"
#define MAX_PAYLOAD_SIZE 1024
void handle_client(int client_fd) {
    uint16_t type;
    uint32_t len;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    
    printf("Client connected\n");
    
    // // 测试1: 接收普通数据包
    // if (net_recv_packet(client_fd, &type, payload, &len, MAX_PAYLOAD_SIZE) != APP_OK) {
    //     printf("Failed to receive initial packet\n");
    //     goto cleanup;
    // }
    // printf("Received packet - Type: %u, Length: %u, Content: %.*s\n", 
    //        type, len, (int)len, payload);
    
    // // 测试2: 发送响应包
    // const char *response = "Server acknowledgment";
    // if (net_send_packet(client_fd, 0xA001, response, strlen(response)) != APP_OK) {
    //     printf("Failed to send response packet\n");
    //     goto cleanup;
    // }
    
    // 测试3: 接收空负载包
    if (net_recv_packet(client_fd, &type, NULL, &len, 0) != APP_OK) {
        printf("Failed to receive empty payload packet\n");
        goto cleanup;
    }
    printf("Received empty payload packet - Type: %u\n", type);
    
    // 测试4: 发送大负载包
    char large_payload[MAX_PAYLOAD_SIZE];
    memset(large_payload, 'X', sizeof(large_payload));
    if (net_send_packet(client_fd, 0xA002, large_payload, sizeof(large_payload)) != APP_OK) {
        printf("Failed to send large payload packet\n");
        goto cleanup;
    }
    
    // 测试5: 接收终止包
    if (net_recv_packet(client_fd, &type, payload, &len, MAX_PAYLOAD_SIZE) != APP_OK) {
        printf("Failed to receive termination packet\n");
        goto cleanup;
    }
    printf("Received termination packet - Type: %u\n", type);

cleanup:
    net_close(client_fd);
    printf("Client disconnected\n");
}

int main(int argc, char *argv[]) {
    int listen_fd, conn_fd;
    listen_fd = net_listen(12345);
    if (listen_fd < 0) {
        perror("Failed to listen");
        return -1;
    }
    printf("Listening on port 12345\n");
    
    while(1) {
        conn_fd = net_accept(listen_fd);
        if (conn_fd < 0) {
            perror("Failed to accept connection");
            continue;
        }
        printf("Accepted connection\n");
        
        // 先接收长度前缀
        uint32_t msg_len;
        if (net_recv_all(conn_fd, &msg_len, sizeof(msg_len)) < 0) {
            perror("Failed to receive length");
            net_close(conn_fd);
            continue;
        }
        msg_len = ntohl(msg_len); // 转换网络字节序
        
        // 接收实际消息
        char buf[1024];
        if (msg_len >= sizeof(buf)) {
            fprintf(stderr, "Message too long\n");
            net_close(conn_fd);
            continue;
        }
        
        if (net_recv_all(conn_fd, buf, msg_len) < 0) {
            perror("Failed to receive data");
            net_close(conn_fd);
            continue;
        }
        buf[msg_len] = '\0'; // 确保字符串终止
        
        printf("Received %d bytes: %s\n", msg_len, buf);
        
        // 发送响应
        const char *response = "Hello, client!";
        uint32_t resp_len = strlen(response);
        uint32_t net_len = htonl(resp_len);
        
        if (net_send_all(conn_fd, &net_len, sizeof(net_len)) < 0 ||
            net_send_all(conn_fd, response, resp_len) < 0) {
            perror("Failed to send response");
        } else {
            printf("Sent response: %s\n", response);
        }
        
        handle_client(conn_fd);
        net_close(conn_fd);
        printf("Closed connection\n");
    }
    
    return 0;
}