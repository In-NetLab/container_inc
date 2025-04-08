#include "exchange.h"
#include "type.h"

#include <stdio.h>

int son_count;
struct TableInitItem sons[10];
int is_root;
struct TableInitItem father;

pack_t receive_pack;

void read_table_init_item(struct TableInitItem *it) {
    scanf("%d", &it->src_ip);
    scanf("%d", &it->dst_ip);
    scanf("%d", &it->dst_qp);
    scanf("%d", &it->connection);
    scanf("%d", &it->is_leaf);
}

void read_init_data() {
    scanf("%d", &son_count);
    for(int i = 0; i < son_count; i++) {
        read_table_init_item(sons + i);
    }
    scanf("%d", &is_root);
    if(!is_root) {
        read_table_init_item(&father);
    }
}

void read_receive_pack() {
    scanf("%d", &receive_pack.basic_info.src_ip);
    scanf("%d", &receive_pack.basic_info.dst_ip);
    scanf("%d", &receive_pack.basic_info.dst_qp);
    scanf("%d", &receive_pack.basic_info.ack);
    scanf("%d", &receive_pack.id);
    scanf("%d", &receive_pack.val);
}

int main() {
    read_init_data();
    if(!is_root)
        init_table(son_count, sons, &father, 10);
    else
        init_table(son_count, sons, NULL, 10);
    for(;;) {
        read_receive_pack();
        on_receive_pack(receive_pack);
    }
}