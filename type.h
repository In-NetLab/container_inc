#ifndef TYPE_H
#define TYPE_H

#include "exchange.h"

typedef int ip_t;
typedef int qp_t;
typedef int eth_t;
typedef int pack_t;
typedef int val_t;
// ip_t, qp_t 需要能支持复制、比较（下面的match函数）
// eth_t 需要支持复制、send函数
// pack_t 需要能从里面弄出简化的PackInfo
// val_t 参与运算的数据类型

int match_ip(ip_t a, ip_t b) {
    return a == b;
}

int match_qp(qp_t a, qp_t b) {
    return a == b;
}

struct PackInfo from_pack(pack_t pack);

#endif