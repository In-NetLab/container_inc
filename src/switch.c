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
#include "rule.h"

// =========================== 配置信息(yaml or 控制器, 暂时硬编码) =======================
#define N 16  // 交换机上各个数组的长度
#define FAN_IN 2  // 交换机子节点个数
#define Idx(psn) ((psn) % N)

// =====================================================================================

typedef struct {
    int len;
    int packet_type;
    uint32_t buffer[1111];
} agg_buffer_t;


// ============================ 静态分配全局变量 ==============================
// 通信组
struct iccl_communicator* comms[FAN_IN];
// 入流: FAN_IN个 报文抵达数组: 0-1计数器, 标识上行数据是否到达 
int arrival_state[FAN_IN][N];
// 出流: 时间戳数组
int64_t ts_buffer[FAN_IN + 1][N];
// 出流: 广播确认报文抵达数组: 0-1计数器, 标识发送广播报文后, 是否收到ACK
int r_arrival_state[FAN_IN][N];

// 每组: 聚合缓冲区: 聚合器, 用于聚合(AllReduce累加即可)
agg_buffer_t agg_buffer[N];
// 每组: 聚合度数组: 计数器, 标识当前有多少上行数据已经参与聚合(应该就等于报文抵达数组列求和)
int agg_degree[N];
pthread_mutex_t agg_mutex = PTHREAD_MUTEX_INITIALIZER;
// 每组: 广播缓冲区: 聚合总结果(下行的?)
agg_buffer_t bcast_buffer[N];
// 每组: 广播报文抵达数组: 0-1计数器, (抵达是指: 全局聚合结果到了本交换机)
int bcast_arrival_state[N];
// 每组: 聚合结果广播度数组: 计数器, 标识聚合结果被多少子节点收到(应该是收到多少ACK??等于确认报文抵达数组列和)
int r_degree[N];
// 每组: 聚合号数组: PSN, 记录当前位置聚合器中的数据报文的序列号(不能用索引idx, idx=(PSN % size), 这个size就是数组长度N)
int agg_psn[N];

// conns[FAN_IN] 为父节点
connection_t conns[FAN_IN + 1];
int root; // 1表示根交换机

rule_table_t table;

// =====================================================================================



// =============================== helper ===============================
void init_all() {
    // 此处修改连接配置
    root = 1;
    uint8_t peer_macs[FAN_IN + 1][6] = {
        {0x52, 0x54, 0x00, 0x52, 0x5d, 0xae},
        {0x52, 0x54, 0x00, 0x5e, 0x4c, 0xb0},
        {}
    };
    char *peer_ips[FAN_IN + 1] = {
        "10.50.183.49",
        "10.50.183.102",
        ""
    };
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root == 1 && i == FAN_IN)
            continue;
        
        memcpy(conns[i].device, "ens3", 4);
        
        uint8_t my_mac[6] = {0x52, 0x54, 0x00, 0x46, 0x57, 0x82};
        // uint8_t peer_mac[6] = {0x52, 0x54, 0x00, 0xdf, 0x0c, 0x28};
        memcpy(conns[i].my_mac, my_mac, 6);
        memcpy(conns[i].peer_mac, peer_macs[i], 6);

        conns[i].my_ip = get_ip("10.50.183.69");
        // conns[i].peer_ip = get_ip("10.50.183.146");
        conns[i].peer_ip = get_ip(peer_ips[i]);

        conns[i].my_port = 23333 + i;
        conns[i].peer_port = 4791;

        conns[i].my_qp = 28 + i;
        conns[i].peer_qp = 0x11; // 待填
        
        conns[i].psn = 0;
        conns[i].msn = 0;
        conns[i].ok = 0;

        print_connection(i, &conns[i]);

        char errbuf[PCAP_ERRBUF_SIZE];
        // handles[i] = pcap_open_live(conns[i].device, BUFSIZ, 1, 1, errbuf);
        conns[i].handle = pcap_create(conns[i].device, errbuf);
        pcap_set_snaplen(conns[i].handle, BUFSIZ);
        pcap_set_promisc(conns[i].handle, 1);
        pcap_set_timeout(conns[i].handle, 1);  // 1ms timeout
        pcap_set_immediate_mode(conns[i].handle, 1);
        pcap_activate(conns[i].handle);

        if (conns[i].handle == NULL) {
            fprintf(stderr, "Could not open device: %s, err: %s\n", conns[i].device, errbuf);
            return;
        }
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

    memset(&table, 0, sizeof(table));
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root == 1 && i == FAN_IN)
            continue;

        rule_t rule;
        rule.src_ip = get_ip(peer_ips[i]);
        rule.dst_ip = get_ip("10.50.183.69");
        rule.id = i;
        rule.direction = DIR_UP;
        rule.ack_conn = &conns[i];
        rule.out_conns_cnt = 0;
        if(root == 1 || (root == 0 && i == FAN_IN)) {
            // 1. 对于根交换机，所有上行入流的出流均是广播子节点
            // 2. 对于中间交换机的下行入流的出流均是广播子节点
            for(int j = 0; j < FAN_IN; j++) { // 广播
                rule.out_conns[j] = &conns[j];
                rule.out_conns_cnt++;
            }
        } else {
            // 中间交换机的上行入流
            rule.out_conns[0] = &conns[FAN_IN];
            rule.out_conns_cnt = 1;
        }
        
        add_rule(&table, &rule);
    }
}

void forwarding(rule_t* rule, uint32_t psn, uint32_t type, uint32_t *data, int len, int packet_type) {
    int id = rule->id;
    LOG_FUNC_ENTRY(id);
    log_write(id, "conn_id: %d, forwarding... psn: %d, type: %d, len: %d\n", id, psn,type, len);

    if(type == PACKET_TYPE_ACK) {
        connection_t* conn = rule->ack_conn;

        uint8_t packet[2048];
        int size = build_eth_packet(
            packet, type, (char*)data, len * sizeof(uint32_t),
            conn->my_mac, conn->peer_mac,
            conn->my_ip, conn->peer_ip,
            conn->my_port, conn->peer_port,
            conn->peer_qp, psn, psn + 1, packet_type
        );

        pcap_t *handle = rule->ack_conn->handle;
        if (pcap_sendpacket(handle, (u_char *)packet, size) == -1) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }

    } else if(type == PACKET_TYPE_DATA) {
        for(int i = 0; i < rule->out_conns_cnt; i++) {
            connection_t* conn = rule->out_conns[i];

            uint8_t packet[2048];
            int size = build_eth_packet(
                packet, type, (char*)data, len * sizeof(uint32_t),
                conn->my_mac, conn->peer_mac,
                conn->my_ip, conn->peer_ip,
                conn->my_port, conn->peer_port,
                conn->peer_qp, psn, psn + 1, packet_type
            );

            pcap_t *handle = rule->out_conns[i]->handle;
            // pcap_sendpacket(handle, (u_char *)(packet), size);
            if (pcap_sendpacket(handle, (u_char *)packet, size) == -1) {
                fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
            }
        }
    } else {
        assert(false);
    }
    LOG_FUNC_EXIT(id);
}

int cache(rule_t* rule, uint32_t psn, uint32_t *data, int len, int packet_type, bool revert) {
    // 缓存数据
    for(int i = 0; i < len; i++) {
        bcast_buffer[Idx(psn)].buffer[i] = revert ? ntohl(data[i]) : data[i];;
    }
    bcast_buffer[Idx(psn)].len = len;
    bcast_buffer[Idx(psn)].packet_type = packet_type;
    
    // 广播
    printf("broadcast... psn: %d\n", psn);
    forwarding(rule, psn, PACKET_TYPE_DATA, bcast_buffer[Idx(psn)].buffer, len, packet_type);
}

int aggregate(rule_t* rule, uint32_t psn, uint32_t *data, int len, int packet_type) {
    int id = rule->id;
    // assert(conn_id == id);
    LOG_FUNC_ENTRY(id);

    pthread_mutex_lock(&agg_mutex);
    for(int i = 0; i < len; i++) {
        agg_buffer[Idx(psn)].buffer[i] += ntohl(data[i]);
    }
    agg_buffer[Idx(psn)].len = len;
    agg_buffer[Idx(psn)].packet_type = packet_type;
    agg_degree[Idx(psn)]++;
    pthread_mutex_unlock(&agg_mutex);

    if(agg_degree[Idx(psn)] == FAN_IN) {
        // forwarding
        if(root == 1) {
            // 对于单(根)交换机, agg buffer -> bcast buffer
            if (bcast_arrival_state[Idx(psn)] == 1) {
            } else {
                bcast_arrival_state[Idx(psn)] = 1;
                cache(rule, psn, agg_buffer[Idx(psn)].buffer, len, packet_type, false);
            }
        } else {
            // 向上传
            forwarding(rule, psn, PACKET_TYPE_DATA, agg_buffer[Idx(psn)].buffer, len, agg_buffer[Idx(psn)].packet_type);
            // 时间戳
        }
        log_write(id, "agg over...\n");
        
    }
    LOG_FUNC_EXIT(id);
}

int retransmit(rule_t* rule, uint32_t psn) {
    int id = rule->id;
    // assert(conn_id == id);
    LOG_FUNC_ENTRY(id);
    if (bcast_arrival_state[Idx(psn)] == 1) {
        // 已有完整聚合结果
        forwarding(rule, agg_psn[Idx(psn)], PACKET_TYPE_DATA, bcast_buffer[Idx(psn)].buffer, bcast_buffer[Idx(psn)].len, bcast_buffer[Idx(psn)].packet_type);
    } else if (agg_degree[Idx(psn)] == FAN_IN) {
        // 完成本节点聚合
        // 单节点此处的本质是 agg buffer -> bcast buffer
        if(root == 1) {
            assert(0);
        } else {
            // 向上重传
            forwarding(rule, agg_psn[Idx(psn)], PACKET_TYPE_DATA, agg_buffer[Idx(psn)].buffer, agg_buffer[Idx(psn)].len, agg_buffer[Idx(psn)].packet_type);
            // 时间戳
        }
    } else if (arrival_state[Idx(psn)] == 0) {
        // 尚未收到子节点数据, 向下NAK
        forwarding(rule, agg_psn[Idx(psn)], PACKET_TYPE_NAK, NULL, 0, 0);
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

    rule_t* rule = lookup_rule(&table, ip->src_ip, ip->dst_ip);
    assert(rule != NULL);

    uint32_t psn = ntohl(bth->apsn) & 0x00FFFFFF; // TODO
    log_write(id, "psn: %u\n", psn);

    if(bth->opcode == 0x04 || bth->opcode == 0x00 || bth->opcode == 0x01 || bth->opcode == 0x02) { // rc send only
        uint32_t* data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4) / sizeof(uint32_t); // icrc = 4
        log_write(id, "udp len: %d, data_len: %d\n", udp->length, data_len);

        if(rule->direction == DIR_DOWN) {
            log_write(id, "downstream data...\n");
            // 下行数据, 广播
            pthread_mutex_lock(&agg_mutex);
            if (psn < agg_psn[Idx(psn)]) {
                // 滞后
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "lag\n");
                forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
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
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    bcast_arrival_state[Idx(psn)] = 1;

                    // 发送ACK
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                    // 缓存模块
                    cache(rule, psn, data, data_len, bth->opcode, true);
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
                forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
            } else if (psn > agg_psn[Idx(psn)]) {
                // 超前
                // 重传模块
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "ahead\n");
                retransmit(rule, psn);
            } else {
                // 持平
                pthread_mutex_unlock(&agg_mutex);
                log_write(id, "equal\n");
                if (arrival_state[id][Idx(psn)] == 1 || bcast_arrival_state[Idx(psn)] == 1) {
                    // 重传 -> or条件如何理解
                    log_write(id, "retransmit\n");
                    // 发送ACK
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                    // 重传模块
                    retransmit(rule, psn);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    arrival_state[id][Idx(psn)] = 1;
                    r_arrival_state[id][Idx(psn)] = 0;

                    // 发送ACK
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                    // 聚合模块
                    aggregate(rule, psn, data, data_len, bth->opcode);
                }
            }
        }
    } else if(bth->opcode == 0x11) { // rc ack
        aeth_t* aeth = (aeth_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));

        if(rule->direction == DIR_DOWN) {
            // 下行ACK
            log_write(id, "downstream ack...\n");
            if(aeth->syn_msn == 0x00000000) {
                // 收到ACK
                if (psn == agg_psn[Idx(psn)]) {
                    // 计时器取消
                    ts_buffer[rule->id][Idx(psn)] = 0;
                }
            } else {
                // NAK
                if (psn == agg_psn[Idx(psn)] && bcast_arrival_state[Idx(psn)] == 0) {
                    retransmit(rule, psn);
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
                    ts_buffer[id][Idx(psn)] = 0;
    
                    if (r_degree[Idx(psn)] == FAN_IN) {
                        // 说明该psn广播完成
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
                    retransmit(rule, psn);
                }
            }
        }
    }
    LOG_FUNC_EXIT(id);
}


void *background_receiving(void *arg) {
    int id = (int)(intptr_t)arg;
    printf("thread %d start...\n", id);
    connection_t* conn = &conns[id];
    
    pcap_t *handle = conn->handle;

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

// void *polling_thread(void *arg) {
//     while(true) {
//         for(int i = 0; i < FAN_IN; i++) {
//             for(int j = 0; j < N; j++) {
//                 uint64_t now_ts = get_now_ts();
//                 if(ts_buffer[i][j] != 0 && now_ts - ts_buffer[i][j] > 100) {
//                     int tmp = j;
//                     printf("timeout, conn id: %d, n: %d, agg psn: %d, pack type: %d\n", i, tmp, agg_psn[tmp], bcast_buffer[tmp].packet_type);
//                     forwarding(i, agg_psn[tmp], PACKET_TYPE_DATA, bcast_buffer[tmp].buffer, bcast_buffer[tmp].len, bcast_buffer[tmp].packet_type);
//                     // 主动重传
//                     // int tmp = j;
//                     // while(true) {
//                     //     if(bcast_buffer[tmp].packet_type == 0x00) {
//                     //         break;
//                     //     } else {
//                     //         tmp--;
//                     //         if(tmp < 0)
//                     //             tmp = N - 1;
//                     //     }
//                     // }
//                     // while(true) {
//                     //     printf("timeout, conn id: %d, n: %d, agg psn: %d, pack type: %d\n", i, tmp, agg_psn[tmp], bcast_buffer[tmp].packet_type);
//                     //     forwarding(i, agg_psn[tmp], PACKET_TYPE_DATA, bcast_buffer[tmp].buffer, bcast_buffer[tmp].len, bcast_buffer[tmp].packet_type);
//                     //     if(bcast_buffer[tmp].packet_type == 0x02) {
//                     //         break;
//                     //     } else {
//                     //         tmp++;
//                     //         if(tmp >= N)
//                     //             tmp = 0;
//                     //     }
//                     // }
//                 }
//             }
//         }

//         usleep(10000); // 10ms轮询一次
//     }
    
// }

// =====================================================================================



int main() {
    if (log_init("/home/ubuntu/switch.log") != 0) {
        fprintf(stderr, "Failed to open log file\n");
        return 1;
    }

    init_all();

    pthread_t receivers[FAN_IN];
    pthread_t polling;

    // 接收线程
    for(int i = 0; i < FAN_IN; i++) {
        pthread_create(&receivers[i], NULL, background_receiving, (void *)(intptr_t)i);

    }
    // pthread_create(&polling, NULL, polling_thread, NULL);

    for(int i = 0; i < FAN_IN; i++) {
        pthread_join(receivers[i], NULL);
    }
    // pthread_join(polling, NULL);

    log_close();
    
    return 0;
}