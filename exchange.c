#include "exchange.h"
#include "type.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

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
    struct TableForwardItem ans;
    ans.connection = init.connection;
    ans.dst_qp = init.dst_qp;
    if(reverse) {
        ans.src_ip = init.dst_ip;
        ans.dst_ip = init.src_ip;
    }
    else {
        ans.src_ip = init.src_ip;
        ans.dst_ip = init.dst_ip;
    }
    return ans;
}

static struct TableMatchItem get_match_item(struct TableInitItem init, int ack) {
    struct TableMatchItem ans;
    ans.ack = ack;
    ans.dst_qp = init.dst_qp;
    ans.src_ip = init.src_ip;
    ans.dst_ip = init.dst_ip;
    return ans;
}

static struct PackInfo get_pack(struct TableForwardItem fwd, int ack, int id, int val) {
    struct PackInfo ans;
    ans.basic_info.ack = ack;
    ans.basic_info.src_ip = fwd.src_ip;
    ans.basic_info.dst_ip = fwd.dst_ip;
    ans.basic_info.dst_qp = fwd.dst_qp;
    ans.id = id;
    ans.val = val;
    return ans;
} 

struct TableItem {
    struct TableMatchItem matched;
    int forward_cnt;
    enum direction_t dir;
    struct TableForwardItem forward_list[MAX_FAN_IN];
};

static struct TableItem table[TABLE_CAPACITY];
static int table_size = 0;
static int fan_in = 0;
static int window = 0;
static int half_window = 0;

static qp_t son_qps[MAX_FAN_IN];
static int ArrivalState[MAX_FAN_IN][MAX_W];
static int AggBuffer[MAX_W];
static int Degree[MAX_W];



// son 和 father 分别表示下层和上层连接，其中下层可能有多个
// 所有TableInitItem的dst_ip都是当前交换机，src_ip是与之连接的结点
void init_table(int son_count, struct TableInitItem *sons, struct TableInitItem *father, int window_size) {
    assert(window_size % 2 == 0);
    window = window_size;
    half_window = window / 2;
    assert(son_count > 0);
    fan_in = son_count;
    // add data handling
    for(int i = 0; i < son_count; i++) {
        son_qps[i] = sons[i].dst_qp;
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
    struct PackInfo pack_info = from_pack(pack);
    int match_idx = -1;
    for(int i = 0; i < table_size; i++) {
        if(is_matched(table[i].matched, pack_info.basic_info)) {
            match_idx = i;
            break;
        }
    }
    if(match_idx == -1) return; // ignore unmatched packs
    if(table[match_idx].matched.ack) { // send ack back
        for(int i = 0; i < table[match_idx].forward_cnt; i++) {
            send_pack(get_pack(table[match_idx].forward_list[i], 1, pack_info.id, -1));
        }
    }
    if(table[match_idx].dir == DOWN) { // broadcast
        for(int i = 0; i < table[match_idx].forward_cnt; i++) {
            send_pack(get_pack(table[match_idx].forward_list[i], 0, pack_info.id, pack_info.val));
        }
    }
    // aggregate
    int pkid = pack_info.id;
    int get_qp_id = -1;
    for(int i = 0; i < fan_in; i++) if(match_qp(pack_info.basic_info.dst_qp, son_qps[i])) {
        get_qp_id = i;
        break;
    }
    assert(get_qp_id != -1);
    if(ArrivalState[get_qp_id][pkid % window] == 0) {
        ArrivalState[get_qp_id][pkid % window] = 1;
        ArrivalState[get_qp_id][(pkid + half_window) % window] = 0;

        Degree[pkid % window]++;
        AggBuffer[pkid % window] += pack_info.val;

        if(Degree[pkid % window] == fan_in) {
            Degree[(pkid + half_window) % window] = 0;
            AggBuffer[(pkid + half_window) % window] = 0;
        }
    }

    if(Degree[pkid % window] == fan_in) {
        int val = AggBuffer[pkid % window]; // get aggregate value
        for(int i = 0; i < table[match_idx].forward_cnt; i++) {
            send_pack(get_pack(table[match_idx].forward_list[i], 0, pkid, val));
        }
    }
}