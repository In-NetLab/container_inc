#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <assert.h>
#include "api.h"
#include "util.h"
#include "log.h"

// =========================== 配置信息(yaml or 控制器, 暂时硬编码) =======================
#define N 16  // 交换机上各个数组的长度
#define FAN_IN 2  // 交换机子节点个数
#define Idx(psn) ((psn) % N)

// =====================================================================================

typedef struct {
    int len;
    uint32_t buffer[1024];
} agg_buffer_t;


// ============================ 静态分配全局变量 ==============================
// 通信组
struct iccl_communicator* comms[FAN_IN];
// 入流: FAN_IN个 报文抵达数组: 0-1计数器, 标识上行数据是否到达 
int arrival_state[FAN_IN][N];
// 出流: 时间戳数组
int64_t ts_buffer[FAN_IN][N];
// 出流: 广播确认报文抵达数组: 0-1计数器, 标识发送广播报文后, 是否收到ACK?
int r_arrival_state[FAN_IN][N];

// 每组: 聚合缓冲区: 聚合器, 用于聚合(AllReduce累加即可)
agg_buffer_t agg_buffer[N];
// 每组: 聚合度数组: 计数器, 标识当前有多少上行数据已经参与聚合(应该就等于报文抵达数组列求和??)
int agg_degree[N];
pthread_mutex_t agg_mutex = PTHREAD_MUTEX_INITIALIZER;
// 每组: 广播缓冲区: 聚合总结果(下行的?)
agg_buffer_t bcast_buffer[N];
// 每组: 广播报文抵达数组: 0-1计数器, (抵达是指: 上面的聚合结果到了本交换机??)
int bcast_arrival_state[N];
// 每组: 聚合结果广播度数组: 计数器, 标识聚合结果被多少子节点收到(应该是收到多少ACK??等于确认报文抵达数组列和??)
int r_degree[N];
// 每组: 聚合号数组: PSN, 记录当前位置聚合器中的数据报文的序列号(不能用索引idx, idx=(PSN % size), 这个size是不是就是数组长度?)
int agg_psn[N];

connection conns[FAN_IN];
connection conn_father;
int root; // 1表示根交换机

pcap_t *handles[FAN_IN + 1];

// =====================================================================================



// =============================== helper ===============================
void init_all() {
    // 此处修改连接配置
    root = 1;
    uint8_t peer_macs[FAN_IN][6] = {
        {0x52, 0x54, 0x00, 0xdf, 0x0c, 0x28},
        {0x52, 0x54, 0x00, 0x00, 0xf9, 0xf3},
    };
    char *peer_ips[FAN_IN] = {
        "10.50.183.146",
        "10.50.183.234",
    };
    for(int i = 0; i < FAN_IN; i++) {
        memcpy(conns[i].device, "ens3", 4);
        
        uint8_t my_mac[6] = {0x52, 0x54, 0x00, 0xba, 0xc7, 0x53};
        // uint8_t peer_mac[6] = {0x52, 0x54, 0x00, 0xdf, 0x0c, 0x28};
        memcpy(conns[i].my_mac, my_mac, 6);
        memcpy(conns[i].peer_mac, peer_macs[i], 6);

        conns[i].my_ip = get_ip("10.50.183.171");
        // conns[i].peer_ip = get_ip("10.50.183.146");
        conns[i].peer_ip = get_ip(peer_ips[i]);

        conns[i].my_port = 23333 + i;
        conns[i].peer_port = 4791;

        conns[i].my_qp = 28 + i;
        conns[i].peer_qp = 0; // 待填
        
        conns[i].psn = 0;
        conns[i].msn = 0;
        conns[i].ok = 0;

        print_connection(i, &conns[i]);
    }
    // gender = 1;               
    // ip_p = "10.50.183.146";
    memset(arrival_state, 0, sizeof(arrival_state));
    memset(ts_buffer, 0, sizeof(ts_buffer));
    memset(r_arrival_state, 0, sizeof(r_arrival_state));
    memset(agg_buffer, 0, sizeof(agg_buffer));
    memset(agg_degree, 0, sizeof(agg_degree));
    memset(bcast_buffer, 0, sizeof(bcast_buffer));
    memset(bcast_arrival_state, 0, sizeof(bcast_arrival_state));
    memset(r_degree, 0, sizeof(r_degree));
    memset(agg_psn, 0, sizeof(agg_psn));
    for(int i = 0; i < N; i++) {
        agg_psn[i] = i;
    }


    // 通信初始化
    // for(int i = 0; i < FAN_IN; i++) {
    //     if(i == 1)
    //         ip_p = "10.50.183.234";
    //     struct iccl_group *group = iccl_group_create(i + 1);
    //     comms[i] = iccl_communicator_create(group, 64);
    // }
    int handle_num = (root == 1) ? FAN_IN : FAN_IN + 1;
    for(int i = 0; i < handle_num; i++) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handles[i] = pcap_open_live(conns[i].device, BUFSIZ, 1, 1000, errbuf);
        if (handles[i] == NULL) {
            fprintf(stderr, "Could not open device: %s, err: %s\n", conns[i].device, errbuf);
            return;
        }
    }
}

void forwarding(int conn_id, uint32_t psn, uint32_t type, uint32_t *data, int len) {
    LOG_FUNC_ENTRY(conn_id);
    log_write(conn_id, "conn_id: %d, forwarding... psn: %d, type: %d, len: %d\n", conn_id, psn,type, len);
    // 构造packet
    connection* conn;
    if(conn_id != FAN_IN)
        conn = &conns[conn_id];
    else
        conn = &conn_father;
    
    uint8_t packet[2048];
    int size = build_eth_packet(
        packet, type, (char*)data, len * sizeof(uint32_t),
        conn->my_mac, conn->peer_mac,
        conn->my_ip, conn->peer_ip,
        conn->my_port, conn->peer_port,
        conn->peer_qp, psn, psn + 1
    );
    // print_all(conn_id, packet);
    if(type == PACKET_TYPE_DATA)
        sleep(0);
        // usleep(0);

    // 发送
    pcap_t *handle = handles[conn_id];
    // pcap_sendpacket(handle, (u_char *)(packet), size);
    if (pcap_sendpacket(handle, (u_char *)packet, size) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    }
    LOG_FUNC_EXIT(conn_id);
}

void broadcast(uint32_t psn, uint32_t *data, int len) {
    for(int i = 0; i < FAN_IN; i++) {
        forwarding(i, psn, PACKET_TYPE_DATA, data, len);
    }
}

int cache(uint32_t psn, uint32_t *data, int len) {
    // 缓存数据
    for(int i = 0; i < len; i++) {
        bcast_buffer[Idx(psn)].buffer[i] = data[i];
    }
    bcast_buffer[Idx(psn)].len = len;
    
    // 广播
    printf("broadcast... psn: %d\n", psn);
    for(int i = 0; i < len; i++) {
        printf("%u ", bcast_buffer[Idx(psn)].buffer[i]);
    }
    printf("\n");
    broadcast(psn, data, len);
}

int aggregate(int conn_id, uint32_t psn, uint32_t *data, int len) {
    LOG_FUNC_ENTRY(conn_id);
    connection* conn;
    if(conn_id != FAN_IN)
        conn = &conns[conn_id];
    else
        conn = &conn_father;

    pthread_mutex_lock(&agg_mutex);
    for(int i = 0; i < len; i++) {
        agg_buffer[Idx(psn)].buffer[i] += ntohl(data[i]);
    }
    agg_buffer[Idx(psn)].len = len;
    agg_degree[Idx(psn)]++;
    pthread_mutex_unlock(&agg_mutex);

    if(agg_degree[Idx(psn)] == FAN_IN) {
        // forwarding
        if(root == 1) {
            // 对于单(根)交换机, agg buffer -> bcast buffer
            if (bcast_arrival_state[Idx(psn)] == 1) {
            } else {
                bcast_arrival_state[Idx(psn)] = 1;
                cache(psn, agg_buffer[Idx(psn)].buffer, len);
            }
        } else {
            // 向上传
            forwarding(FAN_IN, psn, PACKET_TYPE_DATA, agg_buffer[Idx(psn)].buffer, len);
            // 时间戳
        }
        log_write(conn_id, "agg over...\n");
        
    }
    LOG_FUNC_EXIT(conn_id);
}

int retransmit(int id, uint32_t psn) {
    LOG_FUNC_ENTRY(id);
    if (bcast_arrival_state[Idx(psn)] == 1) {
        // 已有完整聚合结果
        forwarding(id, agg_psn[Idx(psn)], PACKET_TYPE_DATA, bcast_buffer[Idx(psn)].buffer, bcast_buffer[Idx(psn)].len);
    } else if (agg_degree[Idx(psn)] == FAN_IN) {
        // 完成本节点聚合
        // 单节点此处的本质是 agg buffer -> bcast buffer
        if(root == 1) {
            assert(0);
        } else {
            // 向上重传
            forwarding(FAN_IN, agg_psn[Idx(psn)], PACKET_TYPE_DATA, agg_buffer[Idx(psn)].buffer, agg_buffer[Idx(psn)].len);
            // 时间戳
        }
    } else if (arrival_state[Idx(psn)] == 0) {
        // 尚未收到子节点数据, 向下NAK
        forwarding(id, agg_psn[Idx(psn)], PACKET_TYPE_NAK, NULL, 0);
    }

    // 尚未收到其他子节点数据, 丢弃
    LOG_FUNC_EXIT(id);
}


// =====================================================================================




// ================================ 核心线程 接收模块 ===================
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int id = atoi((char*)user_data);
    LOG_FUNC_ENTRY(id);
    // print_all(id, packet);
    // sleep(1);

    eth_header_t* eth = (eth_header_t*)packet;
    ipv4_header_t* ip = (ipv4_header_t*)(packet + sizeof(eth_header_t));
    udp_header_t* udp = (udp_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t));
    bth_header_t* bth = (bth_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t));
    if(conns[id].ok == 0) {
        // 连接建立
        conns[id].ok = 1;
        // conns[id].peer_qp = htonl(bth->qpn) & 0x00FFFFFF;
        conns[id].peer_qp = 0x11;
        printf("peer qp: %u\n", conns[id].peer_qp);

        assert(memcmp(conns[id].my_mac, eth->dst_mac, 6) == 0);
        assert(memcmp(conns[id].peer_mac, eth->src_mac, 6) == 0);
        // for(int i = 0; i < 6; i++) {
        //     conns[id].peer_mac[i] = 0xFF;
        // }
        printf("hello\n");
        printf("my ip: %08x, dst ip: %08x\n\n", conns[id].my_ip, ip->dst_ip);
        assert(conns[id].my_ip == ip->dst_ip);
        assert(conns[id].peer_ip == ip->src_ip);
        // assert(conns[id].peer_qp == conns[id].my_qp);
        
        return;
    }

    uint32_t psn = ntohl(bth->apsn) & 0x00FFFFFF; // TODO
    log_write(id, "psn: %u\n", psn);

    if(bth->opcode == 0x04) { // rc send only
        uint32_t* data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4) / sizeof(uint32_t); // icrc = 4
        log_write(id, "udp len: %d, data_len: %d\n", udp->length, data_len);

        if(id == FAN_IN) {
            log_write(id, "downstream data...\n");
            // 下行数据, 广播
            pthread_mutex_lock(&agg_mutex);
            if (psn < agg_psn[Idx(psn)]) {
                // 滞后
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "lag\n");
                forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
            } else if (psn > agg_psn[Idx(psn)]) {
                // 超前, 不应该出现
                pthread_mutex_unlock(&agg_mutex);
                assert(0);
            } else {
                // 持平
                log_write(id, "equal\n");
                pthread_mutex_unlock(&agg_mutex);
                if (bcast_arrival_state[Idx(psn)] == 1) {
                    // 重传
                    log_write(id, "retransmit\n");
                    forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    bcast_arrival_state[Idx(psn)] = 1;

                    // 发送ACK
                    forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
                    // 缓存模块
                    cache(psn, data, data_len);
                }
            }
        } else {
            // 上行数据, 聚合
            log_write(id, "upstream data...\n");
            pthread_mutex_lock(&agg_mutex);
            if (psn < agg_psn[Idx(psn)]) {
                // 滞后
                // 发送ACK
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "lag\n");
                forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
            } else if (psn > agg_psn[Idx(psn)]) {
                // 超前
                // 重传模块
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "ahead\n");
                retransmit(id, psn);
            } else {
                // 持平
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "equal\n");
                if (arrival_state[id][Idx(psn)] == 1 || bcast_arrival_state[Idx(psn)] == 1) {
                    // 重传 -> or条件如何理解
                    log_write(id, "retransmit\n");
                    // 发送ACK
                    forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
                    // 重传模块
                    retransmit(id, psn);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    arrival_state[id][Idx(psn)] = 1;
                    r_arrival_state[id][Idx(psn)] = 0;

                    // 发送ACK
                    forwarding(id, psn, PACKET_TYPE_ACK, NULL, 0);
                    // 聚合模块
                    aggregate(id, psn, data, data_len);
                }
            }
        }
    } else if(bth->opcode == 0x11) { // rc ack
        aeth_t* aeth = (aeth_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));

        if(id == FAN_IN) {
            // 下行ACK
            log_write(id, "downstream ack...\n");
            if(aeth->syn_msn == 0x00000000) {
                // 收到ACK
                if (psn == agg_psn[Idx(psn)]) {
                    // 计时器取消
                }
            } else {
                // NAK
                if (psn == agg_psn[Idx(psn)] && bcast_arrival_state[Idx(psn)] == 0) {
                    retransmit(id, psn);
                }
            }
        } else {
            // 上行ACK
            pthread_mutex_lock(&agg_mutex);
            if((ntohl(aeth->syn_msn) >> 29) == 0) {
                // 收到ACK
                log_write(id, "upstream ack...\n");
                if (psn == agg_psn[Idx(psn)] && r_arrival_state[id][Idx(psn)] == 0) {
                    r_arrival_state[id][Idx(psn)] = 1;
                    arrival_state[id][Idx(psn)] = 0;
                    r_degree[Idx(psn)] += 1;
    
                    if (r_degree[Idx(psn)] == FAN_IN) {
                        // 说明该psn聚合完成
                        // agg_buffer ...
                        log_write(id, "broadcast over...\n");
                        agg_degree[Idx(psn)] = 0;
                        for(int i = 0; i < agg_buffer[Idx(psn)].len; i++) {
                            agg_buffer[Idx(psn)].buffer[i] = 0;
                        }
                        bcast_arrival_state[Idx(psn)] = 0;
                        r_degree[Idx(psn)] = 0;
                        agg_psn[Idx(psn)] += N; // 开始聚合下一个psn
                    }
                }
                pthread_mutex_unlock(&agg_mutex);
            } else {
                // NAK
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "upstream nak...\n");
                if (psn == agg_psn[Idx(psn)]) {
                    retransmit(id, psn);
                }
            }
        }
    }
    LOG_FUNC_EXIT(id);
}


void *background_receiving(void *arg) {
    int id = (int)(intptr_t)arg;
    printf("thread %d start...\n", id);
    connection* conn;
    if(id == FAN_IN)
        conn = &conn_father;
    else
        conn = &conns[id];
    
    pcap_t *handle;
    if(id == FAN_IN)
        handle = handles[FAN_IN];
    else
        handle = handles[id];

    // 设置过滤器（仅捕获 RoCEv2 流量）
    struct bpf_program fp;
    char filter_exp[100];
    char ip_str[INET_ADDRSTRLEN]; // IPv4 缓冲区大小（16字节）
    if (!inet_ntop(AF_INET, &(conn->peer_ip), ip_str, sizeof(ip_str))) {
        printf("to p err\n");
        return NULL;
    }
    snprintf(filter_exp, sizeof(filter_exp), "udp port 4791 and src host %s", ip_str);
    log_write(id, "filter: %s\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set filter: %s\n", pcap_geterr(handle));
        return NULL;
    }

    // 开始抓包
    printf("================================================\n");
    char str[8];
    sprintf(str, "%d", id);
    pcap_loop(handle, -1, packet_handler, str);

    pcap_close(handle);
    printf("++++++++++++++++++++++++++++++++++++++++++++++++\n");
    
    return NULL;
}

// =====================================================================================



int main() {
    if (log_init("/home/ubuntu/switch.log") != 0) {
        fprintf(stderr, "Failed to open log file\n");
        return 1;
    }

    init_all();

    pthread_t receivers[FAN_IN];

    // 接收线程
    for(int i = 0; i < FAN_IN; i++) {
        pthread_create(&receivers[i], NULL, background_receiving, (void *)(intptr_t)i);

    }

    for(int i = 0; i < FAN_IN; i++) {
        pthread_join(receivers[i], NULL);
    }

    log_close();
    
    return 0;
}