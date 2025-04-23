#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include "util.h"

#define MAX_RULES 100
#define MAX_PORT_NUM 10

enum Direction {
    DIR_UP,
    DIR_DOWN,
};


typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;

    int id; // 子节点编号

    int direction;

    // pcap_t *ack_handle; // 回复ACK的端口 相当于入端口
    connection *ack_conn;
    // pcap_t *out_handles[MAX_PORT_NUM]; // 相当于交换机出端口
    connection *out_conns[MAX_PORT_NUM];
    int out_conns_cnt;
} rule_t;

typedef struct {
    rule_t rules[MAX_RULES];
    int count;
} rule_table_t;

// Rules table;

int match_rule(rule_t* rule, uint32_t src_ip, uint32_t dst_ip);

rule_t* lookup_rule(rule_table_t* table, uint32_t src_ip, uint32_t dst_ip);

int add_rule(rule_table_t* table, const rule_t* rule);
