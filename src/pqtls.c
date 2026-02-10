#include "pqtls.h"

#include "pqtls_record.h"

/**
 * @brief 在已建立的安全会话上发送应用数据（REC_APPDATA）
 */
int pqtls_send_appdata(int fd, PQTLS_Session *sess, uint16_t app_type, const uint8_t *payload, uint32_t payload_len)
{
    return pqtls_record_send_appdata(fd, sess, app_type, payload, payload_len);
}

/**
 * @brief 在已建立的安全会话上接收应用数据（REC_APPDATA）
 */
int pqtls_recv_appdata(int fd, PQTLS_Session *sess, uint16_t *app_type, uint8_t *payload, uint32_t payload_cap,
                       uint32_t *payload_len)
{
    return pqtls_record_recv_appdata(fd, sess, app_type, payload, payload_cap, payload_len);
}

