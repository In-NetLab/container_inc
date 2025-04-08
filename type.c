#include "exchange.h"
#include "type.h"

#include <assert.h>
#include <stdio.h>

int match_ip(ip_t a, ip_t b) {
    return a == b;
}

int match_qp(qp_t a, qp_t b) {
    return a == b;
}

// not implemented
struct PackInfo from_pack(pack_t pack) {
    return pack;
}

void send_pack(struct PackInfo pack_data) {
    printf("sending pack: \n");
    printf("src_ip=%d\n", (int)pack_data.basic_info.src_ip);
    printf("dst_ip=%d\n", (int)pack_data.basic_info.dst_ip);
    printf("dst_qp=%d\n", (int)pack_data.basic_info.dst_qp);
    printf("ack=%d\n", (int)pack_data.basic_info.ack);
    printf("id=%d\n", (int)pack_data.id);
    printf("val=%d\n", (int)pack_data.val);
}