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
#include "thpool.h"
#include "parameter.h"
#include "topo_parser.h"

// =========================== 配置信息(yaml or 控制器, 暂时硬编码) =======================
#define N 300  // 交换机上各个数组的长度
#define FAN_IN 2  // 交换机子节点个数
#define Idx(psn) ((psn) % N)
// =====================================================================================

typedef struct {
    int len;
    int packet_type;
    int state;
    int psn;
    uint32_t buffer[1036];
} agg_buffer_t;

typedef struct {
    int64_t ts;
    rule_t* rule;
    int psn;
} ts_t;


// ============================ 静态分配全局变量 ==============================
// 通信组
struct inccl_communicator* comms[FAN_IN];
// 入流: FAN_IN个 报文抵达数组: 0-1计数器, 标识上行数据是否到达 
int arrival_state[FAN_IN][N];
// 出流: 时间戳数组
ts_t ts_buffer[FAN_IN + 1];
// 出流: 广播确认报文抵达数组: 0-1计数器, 标识发送广播报文后, 是否收到ACK
int r_arrival_state[FAN_IN][N];

// 每组: 聚合缓冲区: 聚合器, 用于聚合(AllReduce累加即可)
agg_buffer_t agg_buffer[N];
// 每组: 聚合度数组: 计数器, 标识当前有多少上行数据已经参与聚合(应该就等于报文抵达数组列求和)
int agg_degree[N];
pthread_mutex_t agg_mutex = PTHREAD_MUTEX_INITIALIZER;
// 每组: 广播缓冲区: 聚合总结果(下行的)
agg_buffer_t bcast_buffer[N];
// 每组: 广播报文抵达数组: 0-1计数器, (抵达是指: 全局聚合结果到了本交换机)
// int bcast_arrival_state[N];
// 每组: 聚合结果广播度数组: 计数器, 标识聚合结果被多少子节点收到(应该是收到多少ACK??等于确认报文抵达数组列和)
int r_degree[N];
pthread_mutex_t r_mutex = PTHREAD_MUTEX_INITIALIZER;
// 每组: 聚合号数组: PSN, 记录当前位置聚合器中的数据报文的序列号(不能用索引idx, idx=(PSN % size), 这个size就是数组长度N)
int agg_epsn[FAN_IN];
int down_epsn;
int latest_ack[FAN_IN];
int down_ack;
// conns[FAN_IN] 为父节点
connection_t conns[FAN_IN + 1];
int root; // 1表示根交换机

rule_table_t table;

threadpool thpool;

int parse_finish = 0;

// =====================================================================================

// =============================== controller ===============================

static void *controller_thread(void *arg){
    const char *controller_ip = (char *)arg;
    int sockfd;
    struct sockaddr_in controller_addr;
    FILE* file;
    char buffer[4096];
    ssize_t bytes_received;
    int switch_id;
    // 创建Socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // 配置控制器地址
    memset(&controller_addr, 0, sizeof(controller_addr));
    controller_addr.sin_family = AF_INET;
    controller_addr.sin_port = htons(CONTROLLER_SWITCH_PORT);
    if (inet_pton(AF_INET, controller_ip, &controller_addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sockfd);
        return NULL;
    }

    // 连接控制器
    if (connect(sockfd, (struct sockaddr*)&controller_addr, sizeof(controller_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return NULL;
    }

    printf("Connected to %s:%d\n", controller_ip, CONTROLLER_SWITCH_PORT);
    // 接收switch_id
    size_t total_received = 0;
    while (total_received < sizeof(switch_id)) {
        ssize_t ret = recv(sockfd, (char*)&switch_id + total_received, sizeof(switch_id) - total_received, 0);
        if (ret <= 0) {
            perror("Failed to receive switch_id");
            fclose(file);
            close(sockfd);
            return NULL;
        }
        total_received += ret;
    }
    printf("recv switch id %d\n", (switch_id));
    // recv yaml file
    receive_file(sockfd, "/home/ubuntu/topology.yaml");

    close(sockfd);

    parse_config("/home/ubuntu/topology.yaml", 10, &root, switch_id, conns);

    return NULL;
}

// =============================== helper ===============================
void init_all(const char *controller_ip) {

    // 创建新线程，连接控制器并初始化路由表
    pthread_t tid_controller;
    if(pthread_create(&tid_controller, NULL, controller_thread, (void *)controller_ip)){
        perror("Thread creation failed");
        return;
    }
    pthread_join(tid_controller, NULL);
    // 此处修改连接配置
    // root = 1;
    // uint8_t peer_macs[FAN_IN + 1][6] = {
    //     {0x52, 0x54, 0x00, 0x52, 0x5d, 0xae},
    //     {0x52, 0x54, 0x00, 0x5e, 0x4c, 0xb0},
    //     {}
    // };
    // char *peer_ips[FAN_IN + 1] = {
    //     "10.50.183.49",
    //     "10.50.183.102",
    //     ""
    // };
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root == 1 && i == FAN_IN)
            continue;
        
        
        
        // uint8_t my_mac[6] = {0x52, 0x54, 0x00, 0x46, 0x57, 0x82};
        // // uint8_t peer_mac[6] = {0x52, 0x54, 0x00, 0xdf, 0x0c, 0x28};
        // memcpy(conns[i].my_mac, my_mac, 6);
        // memcpy(conns[i].peer_mac, peer_macs[i], 6);

        // conns[i].my_ip = get_ip("10.50.183.69");
        // // conns[i].peer_ip = get_ip("10.50.183.146");
        // conns[i].peer_ip = get_ip(peer_ips[i]);

        // conns[i].my_port = 23333 + i;
        // conns[i].peer_port = 4791;

        // conns[i].my_qp = 28 + i;
        // conns[i].peer_qp = 0x11; // 待填
        
        conns[i].psn = 0;
        conns[i].msn = 0;
        conns[i].ok = 0;

        print_connection(i, &conns[i]);

        char errbuf[PCAP_ERRBUF_SIZE];
        conns[i].handle = pcap_create(conns[i].device, errbuf);
        //conns[i].handle = pcap_create("ens3", errbuf);
        pcap_set_snaplen(conns[i].handle, BUFSIZ);
        pcap_set_promisc(conns[i].handle, 1);
        pcap_set_timeout(conns[i].handle, 1);  // 1ms timeout
        pcap_set_immediate_mode(conns[i].handle, 1);
        if (pcap_activate(conns[i].handle) != 0) {
            fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(conns[i].handle));
            return;
        }
        if (conns[i].handle == NULL) {
            fprintf(stderr, "Could not open device: %s, err: %s\n", conns[i].device, errbuf);
            return;
        }
    }
    
    memset(arrival_state, 0, sizeof(arrival_state));
    memset(ts_buffer, 0, sizeof(ts_buffer));
    memset(r_arrival_state, 0, sizeof(r_arrival_state));
    memset(agg_buffer, 0, sizeof(agg_buffer));
    memset(agg_degree, 0, sizeof(agg_degree));
    memset(bcast_buffer, 0, sizeof(bcast_buffer));
    // memset(bcast_arrival_state, 0, sizeof(bcast_arrival_state));
    memset(r_degree, 0, sizeof(r_degree));
    // memset(agg_psn, 0, sizeof(agg_psn));
    // for(int i = 0; i < N; i++) {
    //     agg_psn[i] = i;
    // }
    for(int i = 0; i < FAN_IN; i++) {
        agg_epsn[i] = 0;
        latest_ack[i] = -1;
    }
    down_epsn = 0;
    down_ack = -1;

    memset(&table, 0, sizeof(table));
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root == 1 && i == FAN_IN)
            continue;

        rule_t rule;
        rule.src_ip = conns[i].peer_ip;
        rule.dst_ip = conns[i].my_ip;
        rule.id = i;
        if(i != FAN_IN)
            rule.direction = DIR_UP;
        else
            rule.direction = DIR_DOWN;
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

    init_crc32_table();

    thpool = thpool_init(8);
}

typedef struct {
    connection_t* conn;
    int type;
    void* data;
    int len;
    uint32_t psn;
    int packet_type;
} thread_arg_t;

void send_packet_thread(void* arg) {
    thread_arg_t* t_arg = (thread_arg_t*)arg;
    connection_t* conn = t_arg->conn;

    uint8_t packet[5555];
    int size = build_eth_packet(
        packet, t_arg->type, (char*)t_arg->data, t_arg->len * sizeof(uint32_t),
        conn->my_mac, conn->peer_mac,
        conn->my_ip, conn->peer_ip,
        conn->my_port, conn->peer_port,
        conn->peer_qp, t_arg->psn, t_arg->psn + 1, t_arg->packet_type
    );

    if (pcap_sendpacket(conn->handle, (uint8_t *)packet, size) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(conn->handle));
    }

    return;
}


// 多线程发送封装函数
void send_packets_multithread(rule_t* rule, int type, void* data, int len, uint32_t psn, int packet_type) {
    int cnt = rule->out_conns_cnt;
    pthread_t threads[16];
    thread_arg_t args[16];  // 使用栈分配

    for (int i = 0; i < cnt; i++) {
        args[i].conn = rule->out_conns[i];
        args[i].type = type;
        args[i].data = data;
        args[i].len = len;
        args[i].psn = psn;
        args[i].packet_type = packet_type;

        // if (pthread_create(&threads[i], NULL, send_packet_thread, &args[i]) != 0) {
        //     perror("Failed to create thread");
        // }
        thpool_add_work(thpool, send_packet_thread, &args[i]);
    }

    thpool_wait(thpool);

    // for (int i = 0; i < cnt; i++) {
    //     pthread_join(threads[i], NULL);
    // }
}

void forwarding(rule_t* rule, uint32_t psn, uint32_t type, uint32_t *data, int len, int packet_type) {
    // TODO: 待优化, 尤其 rule 的设计
    int id = rule->id;
    LOG_FUNC_ENTRY(id);
    log_write(id, "conn_id: %d, forwarding... psn: %d, type: %d, len: %d\n", id, psn,type, len);

    if(type == PACKET_TYPE_ACK || type == PACKET_TYPE_NAK) {
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
        if (pcap_sendpacket(handle, (uint8_t *)packet, size) == -1) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }

    } else if(type == PACKET_TYPE_DATA) {
        if(rule->out_conns_cnt == 1) {
            connection_t* conn = rule->out_conns[0];

            uint8_t packet[5555];
            int size = build_eth_packet(
                packet, type, (char*)data, len * sizeof(uint32_t),
                conn->my_mac, conn->peer_mac,
                conn->my_ip, conn->peer_ip,
                conn->my_port, conn->peer_port,
                conn->peer_qp, psn, psn + 1, packet_type
            );

            pcap_t *handle = rule->out_conns[0]->handle;
            // pcap_sendpacket(handle, (uint8_t *)(packet), size);
            if (pcap_sendpacket(handle, (uint8_t *)packet, size) == -1) {
                fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
            }
        } else {
            send_packets_multithread(rule, type, data, len, psn, packet_type);
        }

    } else if (type == PACKET_TYPE_DATA_SINGLE) {
        connection_t* conn = rule->ack_conn;

        uint8_t packet[5555];
        int size = build_eth_packet(
            packet, PACKET_TYPE_DATA, (char*)data, len * sizeof(uint32_t),
            conn->my_mac, conn->peer_mac,
            conn->my_ip, conn->peer_ip,
            conn->my_port, conn->peer_port,
            conn->peer_qp, psn, psn + 1, packet_type
        );

        if (pcap_sendpacket(conn->handle, (uint8_t *)packet, size) == -1) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(conn->handle));
        }

    } else {
        assert(false);
    }
    LOG_FUNC_EXIT(id);
}

int retransmit(rule_t* rule, uint32_t psn) {
    int id = rule->id;
    rule_t* _rule = rule;
    uint32_t _psn = psn;
    LOG_FUNC_ENTRY(id);
    forwarding(_rule, _psn, PACKET_TYPE_DATA_SINGLE, bcast_buffer[Idx(_psn)].buffer, bcast_buffer[Idx(_psn)].len, bcast_buffer[Idx(_psn)].packet_type);
    LOG_FUNC_EXIT(id);
}

int cache(rule_t* rule, uint32_t psn, uint32_t *data, int len, int packet_type, bool revert) {
    // 缓存数据, 此时是收到父节点的全局聚合结果(用于广播的数据)
    // for(int i = 0; i < len; i++) {
    //     bcast_buffer[Idx(psn)].buffer[i] = revert ? ntohl(data[i]) : data[i];;
    // }
    assert(psn == down_epsn);
    down_epsn++;
    memcpy(bcast_buffer[Idx(psn)].buffer, data, len * sizeof(uint32_t));

    bcast_buffer[Idx(psn)].len = len;
    bcast_buffer[Idx(psn)].packet_type = packet_type;
    bcast_buffer[Idx(psn)].state = 1;
    bcast_buffer[Idx(psn)].psn = psn;
    
    // 广播
    printf("broadcast... psn: %d\n", psn);
    forwarding(rule, psn, PACKET_TYPE_DATA, bcast_buffer[Idx(psn)].buffer, len, packet_type);
}

void down_ack_handler(aeth_t* aeth, rule_t* rule, int psn) {
    int id;
    if(rule)
        id = rule->id;
    else
        id = FAN_IN; // 父节点

    if((ntohl(aeth->syn_msn) >> 29) == 0) {
        // 收到ACK
        log_write(id, "downstream ack...\n");
        int tmp = psn;
        if(tmp > down_ack) {
            // 重置计时器
            ts_buffer[id].ts = get_now_ts();
            
            while(1) {
                if(agg_buffer[Idx(tmp)].state == 1 && agg_buffer[Idx(tmp)].psn == tmp) {
                    pthread_mutex_lock(&agg_mutex);
                    agg_degree[Idx(tmp)] = 0;
                    memset(&agg_buffer[Idx(tmp)], 0, sizeof(agg_buffer_t));
                    for(int i = 0; i < FAN_IN; i++) {
                        arrival_state[i][Idx(tmp)] = 0;
                    }
                    pthread_mutex_unlock(&agg_mutex);
                } else {
                    break;
                }

                tmp--;
            }
            
            down_ack = psn;
        }
    } else {
        // NAK
        log_write(id, "downstream nak...\n");
        int tmp = psn - 1;
        if(tmp > down_ack) {
            // 重置计时器
            ts_buffer[id].ts = get_now_ts();
            
            while(1) {
                if(agg_buffer[Idx(tmp)].state == 1 && agg_buffer[Idx(tmp)].psn == tmp) {
                    pthread_mutex_lock(&agg_mutex);
                    agg_degree[Idx(tmp)] = 0;
                    memset(&agg_buffer[Idx(tmp)], 0, sizeof(agg_buffer_t));
                    for(int i = 0; i < FAN_IN; i++) {
                        arrival_state[i][Idx(tmp)] = 0;
                    }
                    pthread_mutex_unlock(&agg_mutex);
                } else {
                    break;
                }

                tmp--;
            }
            
            down_ack = psn - 1;
        }

        while(1) {
            if(agg_degree[Idx(psn)] == FAN_IN && agg_buffer[Idx(psn)].psn > down_ack) {
                retransmit(rule, psn);
            } else {
                break;
            }
            psn++;
        }
    }
}

void add_payload(uint32_t *restrict dst, const uint32_t *restrict src, int len) {
    for (int i = 0; i < len; i++) {
        dst[i] += src[i];
    }
}


int aggregate(rule_t* rule, uint32_t psn, uint32_t *data, int len, int packet_type) {
    int id = rule->id;
    LOG_FUNC_ENTRY(id);

    pthread_mutex_lock(&agg_mutex);
    // for(int i = 0; i < len; i++) {
    //     agg_buffer[Idx(psn)].buffer[i] += (data[i]);
    // }
    add_payload(agg_buffer[Idx(psn)].buffer, data, len);
    agg_buffer[Idx(psn)].len = len;
    agg_buffer[Idx(psn)].packet_type = packet_type;
    agg_buffer[Idx(psn)].state = 1;
    agg_buffer[Idx(psn)].psn = psn;
    agg_degree[Idx(psn)]++;
    pthread_mutex_unlock(&agg_mutex);

    if(agg_degree[Idx(psn)] == FAN_IN) {
        // forwarding
        if(root == 1) {
            // 对于单(根)交换机, agg buffer -> bcast buffer
            if (bcast_buffer[Idx(psn)].state == 1) {
                assert(0);
            } else {
                // 相当于立刻发生了两件事:
                // 1. 收到下行对应的 ACK
                // 2. 收到下行对应的广播包
                aeth_t aeth;
                aeth.syn_msn = 0; // ACK
                
                cache(rule, psn, agg_buffer[Idx(psn)].buffer, len, packet_type, false);
                down_ack_handler(&aeth, NULL, psn);
            }
        } else {
            // 向上传
            forwarding(rule, psn, PACKET_TYPE_DATA, agg_buffer[Idx(psn)].buffer, len, agg_buffer[Idx(psn)].packet_type);
        }
        log_write(id, "agg over...\n");
        
    }
    LOG_FUNC_EXIT(id);
}

int re_idx[FAN_IN];
rule_t* re_rule[FAN_IN];
uint32_t re_psn[FAN_IN];
void re_thread(void* arg) {
    int id = *(int*)arg;
    log_write(id, "re thread\n");
    rule_t* rule = re_rule[id];
    uint32_t psn = re_psn[id];
    while(1) {
        if(bcast_buffer[Idx(psn)].state == 1 && bcast_buffer[Idx(psn)].psn > latest_ack[id]) {
            retransmit(rule, psn);
        } else {
            break;
        }
        psn++;
    }
    log_write(id, "re thread over\n");
}

// =====================================================================================




// ================================ 核心线程 接收模块 ===================
void packet_handler(uint8_t *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *packet) {
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

    int psn = ntohl(bth->apsn) & 0x00FFFFFF; // TODO
    log_write(id, "psn: %u\n", psn);

    if(bth->opcode == 0x04 || bth->opcode == 0x00 || bth->opcode == 0x01 || bth->opcode == 0x02) { // rc send only
        uint32_t* data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4) / sizeof(uint32_t); // icrc = 4
        log_write(id, "udp len: %d, data_len: %d\n", udp->length, data_len);

        if(rule->direction == DIR_DOWN) {
            log_write(id, "downstream data...\n");
            // 下行数据, 广播
            if (psn < down_epsn) {
                // 滞后
                log_write(id, "lag\n");
                forwarding(rule, down_epsn - 1, PACKET_TYPE_ACK, NULL, 0, 0);
            } else if (psn > down_epsn) {
                log_write(id, "ahead\n");
                forwarding(rule, down_epsn, PACKET_TYPE_NAK, NULL, 0, 0);
            } else {
                // 持平
                log_write(id, "equal\n");
                if (bcast_buffer[Idx(psn)].state == 1) {
                    assert(0); // 这个其实是说明已经快了一轮
                    log_write(id, "retransmit\n");
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    
                    // 发送ACK
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                    // 缓存模块
                    cache(rule, psn, data, data_len, bth->opcode, true); // epsn++
                }
            }
        } else {
            // 上行数据, 聚合
            log_write(id, "upstream data...\n");
            if (psn < agg_epsn[id]) {
                // 滞后
                // 发送ACK
                log_write(id, "lag\n");
                forwarding(rule, agg_epsn[id] - 1, PACKET_TYPE_ACK, NULL, 0, 0);
            } else if (psn > agg_epsn[id]) {
                // 超前/乱序
                log_write(id, "ahead\n");
                forwarding(rule, agg_epsn[id], PACKET_TYPE_NAK, NULL, 0, 0);
            } else {
                // 持平
                log_write(id, "equal\n");
                agg_epsn[id]++;
                if (arrival_state[id][Idx(psn)] == 1) {
                    assert(0); // 这个其实是说明已经快了一轮, 当发送方窗口较小时,不可能发生 => 这里可以加个流控机制
                    log_write(id, "retransmit\n");
                    // 发送ACK
                    forwarding(rule, psn, PACKET_TYPE_ACK, NULL, 0, 0);
                } else {
                    // 首传
                    log_write(id, "first\n");
                    arrival_state[id][Idx(psn)] = 1;
                    // r_arrival_state[id][Idx(psn)] = 0;

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
            down_ack_handler(aeth, rule, psn);
        } else {
            // 上行ACK
            if((ntohl(aeth->syn_msn) >> 29) == 0) {
                // 收到ACK
                log_write(id, "upstream ack...\n");
                int tmp = psn;
                if(psn > latest_ack[id]) {
                    if(r_arrival_state[id][Idx(psn)] == 1 || bcast_buffer[Idx(psn)].psn != psn)
                        return;

                    // 重置计时器
                    ts_buffer[id].ts = get_now_ts();
                    r_arrival_state[id][Idx(psn)] = 1;
                    pthread_mutex_lock(&r_mutex);
                    while(1) {
                        r_degree[Idx(psn)] += 1;
                        if (r_degree[Idx(psn)] == FAN_IN) {
                            // 说明该psn广播完成
                            log_write(id, "psn: %d, broadcast over...\n", psn);
                            r_degree[Idx(psn)] = 0;
                            memset(&bcast_buffer[Idx(psn)], 0, sizeof(agg_buffer_t));
                            for(int i = 0; i < FAN_IN; i++) {
                                r_arrival_state[i][Idx(psn)] = 0;
                            }
                        }

                        psn--;
                        if(psn == latest_ack[id])
                            break;
                    }
                    pthread_mutex_unlock(&r_mutex);
                    latest_ack[id] = tmp;
                }
            } else {
                // NAK
                // pthread_mutex_unlock(&agg_mutex);
                log_write(id, "upstream nak...\n");
                int tmp = psn - 1;
                if(tmp > latest_ack[id]) {
                    pthread_mutex_lock(&r_mutex);
                    while(1) {
                        if(r_arrival_state[id][Idx(tmp)] == 1 || bcast_buffer[Idx(tmp)].psn != tmp)
                            continue;
                        r_arrival_state[id][Idx(tmp)] = 1;
                        r_degree[Idx(tmp)] += 1;
                        if (r_degree[Idx(tmp)] == FAN_IN) {
                            // 说明该psn广播完成
                            log_write(id, "psn: %d, broadcast over...\n", tmp);
                            r_degree[Idx(tmp)] = 0;
                            memset(&bcast_buffer[Idx(tmp)], 0, sizeof(agg_buffer_t));
                            for(int i = 0; i < FAN_IN; i++) {
                                r_arrival_state[i][Idx(tmp)] = 0;
                            }
                        }

                        tmp--;
                        if(tmp == latest_ack[id])
                            break;
                    }
                    pthread_mutex_unlock(&r_mutex);
                    latest_ack[id] = psn - 1;
                }

                // while(1) {
                //     if(bcast_buffer[Idx(psn)].state == 1 && bcast_buffer[Idx(psn)].psn > latest_ack[id]) {
                //         retransmit(rule, psn);
                //     } else {
                //         break;
                //     }
                //     psn++;
                // }
                re_rule[id] = rule;
                re_psn[id] = psn;
                re_idx[id] = id;
                thpool_add_work(thpool, re_thread, &re_idx[id]);
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

void *polling_thread(void *arg) {
    while(1) {
        for(int i = 0; i < FAN_IN; i++) {
            uint64_t now_ts = get_now_ts();
            if(ts_buffer[i].ts != 0 && now_ts - ts_buffer[i].ts > 100) {
                int psn = latest_ack[i] + 1;
                rule_t* rule = &table.rules[i];

                printf("timeout, conn id: %d, psn: %d, pack type: %d\n", i, psn, bcast_buffer[Idx(psn)].packet_type);

                while(1) {
                    if(bcast_buffer[Idx(psn)].state == 1 && bcast_buffer[Idx(psn)].psn > latest_ack[i]) {
                        retransmit(rule, psn);
                    } else {
                        break;
                    }
                    psn++;
                }

                printf("timeout over\n");
            }
        }

        usleep(10000); // 10ms轮询一次
    }
    
}

// =====================================================================================



int main(int argc, char *argv[]) {
    char *controller_ip;
    if(argc != 2) {
        return -1;
    } else {
        controller_ip = argv[1];
    }
    

    if (log_init("/home/ubuntu/switch.log") != 0) {
        fprintf(stderr, "Failed to open log file\n");
        return 1;
    }

    init_all(controller_ip);
    printf("init finish");
    pthread_t receivers[FAN_IN + 1];
    pthread_t polling;

    // 接收线程
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root && i == FAN_IN)
            continue;
        pthread_create(&receivers[i], NULL, background_receiving, (void *)(intptr_t)i);

    }
    // pthread_create(&polling, NULL, polling_thread, NULL);

    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root && i == FAN_IN)
            continue;
        pthread_join(receivers[i], NULL);
    }
    // pthread_join(polling, NULL);

    log_close();
    
    return 0;
}