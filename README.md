```
struct TableInitItem {
    ip_t src_ip;
    ip_t dst_ip;
    qp_t dst_qp;
    eth_t connection;
    int is_leaf;
};
```

初始化转发表时每一个连接用一个结构体表示，其中 `dst_ip` 和 `dst_qp` 是本地的ip和qp

```
struct TableMatchItem {
    ip_t src_ip;
    ip_t dst_ip;
    qp_t dst_qp;
    int ack;
};
```

数据包的基本数据，包含ip, qp, 是否是ack（ack=0表示传数据，ack=1表示ack包），这里如果要加个 `eth_t connection` 也方便

用来匹配转发表中的表项

```
struct PackInfo {
    struct TableMatchItem basic_info;
    int id;
    val_t val;
};
```

转发连接结构体基础上加了 `id` 表示数据包的顺序id，和传输的数据 `val`

所有输入和输出的数据包都可以用这个结构体来抽象

## 需要实现的接口

```
struct PackInfo from_pack(pack_t pack);
void send_pack(struct PackInfo pack_data);
```

分别表示从接收的 `pack_t` 中提取 `PackInfo` 结构体，发送一个 `PackInfo` 表示的包

## 可以调用的接口

```
void init_table(int son_count, struct TableInitItem *sons, struct TableInitItem *father);
void on_receive_pack(pack_t pack);
```

`init_table` 表示初始化表格，前两个参数表示所有儿子节点，最后一个参数表示连接的父节点，父节点指针可以是NULL

`on_receive_pack` 表示收到一个数据包时要做的事