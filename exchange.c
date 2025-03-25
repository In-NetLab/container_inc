#include "exchange.h"
#include "type.h"

#include <assert.h>
#include <stddef.h>

static const int TABLE_CAPACITY = 1024;
static const int MAX_FAN_IN = 10;
static const int MAX_W = 1024;
// 文档里要求必须静态分配，暂时这么写了

// match incoming packs
static int is_matched(struct TableMatchItem a, struct TableMatchItem b) {
    if(!match_ip(a.src_ip, b.src_ip)) return 0;
    if(!match_ip(a.dst_ip, b.dst_ip)) return 0;
    if(!match_qp(a.dst_qp, b.dst_qp)) return 0;
    if(a.ack != b.ack) return 0;
    return 1;
}


// reverse: 是否翻转src_ip和dst_ip
static struct TableForwardItem get_forward_item(struct TableInitItem init, int reverse) {
    // not implemented
    assert(0);
}

static struct TableMatchItem get_match_item(struct TableInitItem init, int ack) {
    // not implemented
}

struct TableItem {
    struct TableMatchItem matched;
    int forward_cnt;
    enum direction_t dir;
    struct TableForwardItem forward_list[MAX_FAN_IN];
};

static struct TableItem table[TABLE_CAPACITY];
static int table_size = 0;

// son 和 father 分别表示下层和上层连接，其中下层可能有多个
// 所有TableInitItem的dst_ip都是当前交换机，src_ip是与之连接的结点
void init_table(int son_count, struct TableInitItem *sons, struct TableInitItem *father) {
    assert(son_count > 0);
    // add data handling
    for(int i = 0; i < son_count; i++) {
        table[table_size].matched = get_match_item(sons[i], 0);
        table[table_size].dir = UP;
        if(father != NULL) {
            table[table_size].forward_cnt = 1;
            table[table_size].forward_list[0] = get_forward_item(*father, 1);
        }
        else {
            table[table_size].forward_cnt = son_count;
            for(int i = 0; i < son_count; i++) {
                table[table_size].forward_list[i] = get_forward_item(sons[i], 1);
            }
        }
        table_size++;
    }
    if(father != NULL) {
        // add down flow data handling
        table[table_size].matched = get_match_item(*father, 0);
        table[table_size].dir = DOWN;
        table[table_size].forward_cnt = son_count;
        for(int i = 0; i < son_count; i++) {
            table[table_size].forward_list[i] = get_forward_item(sons[i], 1);
        }
    }
    // add ack handling
    for(int i = 0; i < son_count; i++) if(sons[i].is_leaf) {
        table[table_size].matched = get_match_item(sons[i], 1);
        table[table_size].dir = UP;
        table[table_size].forward_cnt = 1;
        table[table_size].forward_list[i] = get_forward_item(sons[i], 1);
        table_size++;
    }
}

void on_receive_pack(pack_t pack) {
    // not implemented
    assert(0);
}