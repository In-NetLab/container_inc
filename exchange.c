#include "exchange.h"
#include "type.h"

#include <assert.h>

static const int TABLE_CAPACITY = 1024;
static const int MAX_FAN_IN = 10;
static const int MAX_W = 1024;
// 文档里要求必须静态分配，暂时这么写了

static int is_matched(struct TableMatchItem a, struct TableMatchItem b) {
    // not implemented
    assert(0);
    return 1;
}

struct TableItem {
    struct TableMatchItem matched;
    int forward_cnt;
    struct TableForwardItem forward_list[MAX_FAN_IN];
};

// son 和 father 分别表示下层和上层连接，其中下层可能有多个
void init_table(int son_count, struct TableInitItem *sons, struct TableInitItem *father) {
    // not implemented
    assert(0);
}

void on_receive_pack(pack_t pack) {
    // not implemented
    assert(0);
}