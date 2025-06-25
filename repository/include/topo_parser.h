#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "util.h"

typedef struct {
    int up;
    const char* my_ip;
    const char* my_mac;
    int my_port;
    int my_qp;
    const char* my_name;
    const char* peer_ip;
    const char* peer_mac;
    int peer_port;
    int peer_qp;
} CConnection;

int parse_config(const char* yaml_file, int max_count, int* root, int switch_id, connection_t* conns);
int get_switch_info(const char* yaml_file, int rank, uint32_t *ip, uint32_t *qpnum);

#ifdef __cplusplus
}
#endif

#endif
