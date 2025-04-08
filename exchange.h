#ifndef EXCHANGE_H
#define EXCHANGE_H

#include "type.h"

struct TableMatchItem {
    ip_t src_ip;
    ip_t dst_ip;
    qp_t dst_qp;
    int ack;
};

struct TableForwardItem {
    ip_t src_ip;
    ip_t dst_ip;
    qp_t dst_qp;
    eth_t connection;
};

struct TableInitItem {
    ip_t src_ip;
    ip_t dst_ip;
    qp_t dst_qp;
    eth_t connection;
    int is_leaf;
};

enum direction_t {
    UP,
    DOWN
};

struct PackInfo {
    struct TableMatchItem basic_info;
    int id;
    val_t val;
};

void init_table(int son_count, struct TableInitItem *sons, struct TableInitItem *father, int window_size);
void on_receive_pack(pack_t pack);

#endif