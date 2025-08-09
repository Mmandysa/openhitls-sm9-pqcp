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

// 引入 PQCP KEM 头文件，确保路径和库已配置
#include "pqcp_kem.h"

#define LISTEN_PORT 12345
#define BACKLOG 5
#define BUFFER_SIZE 8192


int main(void) {



    return 0;
}