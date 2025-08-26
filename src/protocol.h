#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

int protocol_rsu_handshake(int fd, 
                           const char *expected_obu_sign_id, 
                           const char *expected_obu_exch_id, 
                           const char *rsu_exch_id, 
                           SessionKeys *ks);

int protocol_obu_handshake(int fd, 
                           const char *sign_id, 
                           const char *exch_id, 
                           const char *rsu_exch_id, 
                           SessionKeys *ks);
#endif
