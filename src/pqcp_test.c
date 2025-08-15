#include "scloud_kem.h"
#include "common.h"
#include <stdio.h>
int main() {
    if (scloud_global_init("/usr/local/lib") != APP_OK) {
        printf("PQCP provider init failed\n"); return -1;
    }
    printf("PQCP provider initialized successfully\n");
    
    


}