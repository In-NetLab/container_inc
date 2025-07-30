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
#include <sys/epoll.h>
#include "api.h"
#include "util.h"
#include "log.h"
#include "rule.h"
#include "thpool.h"
#include "parameter.h"
#include "topo_parser.h"
#include <endian.h>

#define WINDOW_SIZE 8 // window size 
#define N  (2*WINDOW_SIZE) // resource allocated to one group
#define FAN_IN 2  // number of ports - 1
#define PORT_COUNT (FAN_IN + 1)
#define Idx(psn) ((psn) % N)

#define MAX_EVENTS (PORT_COUNT*2)

#define MASK_ALL_FAN_IN (0xffffffff>>(32-FAN_IN))
#define MASK_PORT(port) (0x1<<(port))

enum packet_type {
    UP_DATA, // send or other write packet
    UP_ACK,
    UP_WRITE_FIRST_ONLY,
    DOWN_DATA,
    DOWN_WRITE_FIRST_ONLY,
    DOWN_ACK
};

typedef struct metadata{
    //int group; no use
    int ingress_port;
    enum packet_type type;
    uint8_t opcode;
    int psn;
} metadata_t;


/**
 * resources allocated to each group. There is only one group in our design now.
 */


int aggregator[N][PAYLOAD_LEN / sizeof(int)]; 

reth_header_t reth_keeper[N][FAN_IN]; // every fan-in keep the rkey, addr, length

uint32_t arrival_state[N]; // Max 32 ports, bitmap, need MASK and contain the result from parent, and can use mask to play the role of degree
int degree[N]; // used to process retransmission, only degree % FAN_IN == 0, re-upload



/**
 * in p4,the following topology info is in the form of args of the table actions.
 */
connection_t conns[PORT_COUNT]; // parent connection: conns[FAN_IN]
int root; // 1表示根交换机


int epoll_fd = -1;


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


void init_topology(const char *controller_ip) {

    // 创建新线程，连接控制器并初始化路由表
    pthread_t tid_controller;
    if(pthread_create(&tid_controller, NULL, controller_thread, (void *)controller_ip)){
        perror("Thread creation failed");
        return;
    }
    pthread_join(tid_controller, NULL);

    // create epoll for ports
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1 failed");
        return ;
    }

    // for each port
    for(int i = 0; i < FAN_IN + 1; i++) {
        if(root == 1 && i == FAN_IN)
            continue;

        conns[i].psn = 0;
        conns[i].msn = 0;
        conns[i].ok = 0;

        print_connection(i, &conns[i]);

        char errbuf[PCAP_ERRBUF_SIZE];
        conns[i].handle = pcap_create(conns[i].device, errbuf);
        pcap_set_snaplen(conns[i].handle, BUFSIZ);
        pcap_set_promisc(conns[i].handle, 1);
        pcap_set_timeout(conns[i].handle, 1);  // 1ms timeout
        pcap_set_immediate_mode(conns[i].handle, 1);
        pcap_setnonblock(conns[i].handle, 1, errbuf);
        if (pcap_activate(conns[i].handle) != 0) {
            fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(conns[i].handle));
            return;
        }
        if (conns[i].handle == NULL) {
            fprintf(stderr, "Could not open device: %s, err: %s\n", conns[i].device, errbuf);
            return;
        }

        struct bpf_program fp;
        char filter_exp[100];
        char ip_str[INET_ADDRSTRLEN];
        
        // RoCEv2 filter
        if (!inet_ntop(AF_INET, &(conns[i].peer_ip), ip_str, sizeof(ip_str))) {
            perror("inet_ntop failed");
            continue;
        }
        
        printf("port %d: device: %s\n",i, conns[i].device);
        snprintf(filter_exp, sizeof(filter_exp), "udp port 4791 and src host %s", ip_str);

        if (pcap_compile(conns[i].handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Filter error: %s\n", pcap_geterr(conns[i].handle));
            continue;
        }
        
        if (pcap_setfilter(conns[i].handle, &fp) == -1) {
            fprintf(stderr, "Set filter error: %s\n", pcap_geterr(conns[i].handle));
            pcap_freecode(&fp);
            continue;
        }
        pcap_freecode(&fp);

        // add fd into epoll
        int fd = pcap_get_selectable_fd(conns[i].handle);
        if (fd == -1) {
            fprintf(stderr, "Cannot get selectable file descriptor for %s\n", conns[i].device);
            continue;
        }
        
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.u32 = i;
        
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            perror("epoll_ctl failed");
            close(epoll_fd);
            return;
        }

    }

    memset(aggregator, 0, sizeof(aggregator));
    memset(arrival_state, 0, sizeof(arrival_state));
    memset(reth_keeper,0,sizeof(reth_keeper));
    memset(degree, 0, sizeof(degree));

    init_crc32_table();
}



// value 0 indicates clear, 1 indicates set
static inline void set_arrive_state(int port, int psn){
    arrival_state[Idx(psn)] |= MASK_PORT(port);
}

static inline void clear_state_data(int psn){
    printf("psn to clear: %d\n",psn);
    arrival_state[Idx(psn)] = 0;
    degree[Idx(psn)] = 0;
    memset(reth_keeper[Idx(psn)],0, sizeof(reth_header_t)*FAN_IN);
    int *slot = aggregator[Idx(psn)];
    memset(slot,0,PAYLOAD_LEN);
}

static inline bool recv_from_all_fan_in(int psn){
    return (arrival_state[Idx(psn)] & MASK_ALL_FAN_IN) ==  MASK_ALL_FAN_IN;
}

static inline bool recv_from_port(int port, int psn){
    return arrival_state[Idx(psn)] & MASK_PORT(port);
}

static void send_roce_data(int port, const uint8_t *data, int psn, int len, int opcode){
    connection_t *conn = conns+port;
    uint8_t frame[5555];
    int size = build_eth_packet(
        frame, PACKET_TYPE_DATA, (char*)data, PAYLOAD_LEN,
        conn->my_mac, conn->peer_mac,
        conn->my_ip, conn->peer_ip,
        conn->my_port, conn->peer_port,
        conn->peer_qp, psn, psn + 1, opcode, NULL
    );
    if(pcap_sendpacket(conn->handle, (uint8_t *)frame, size) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(conn->handle));
    }

}

static void send_roce_data_with_reth(int port, const uint8_t *reth, const uint8_t *data, int psn, int len, int opcode){
    connection_t *conn = conns+port;
    uint8_t frame[5555];
    int size = build_eth_packet(
        frame, PACKET_TYPE_RETH, (char*)data, PAYLOAD_LEN,
        conn->my_mac, conn->peer_mac,
        conn->my_ip, conn->peer_ip,
        conn->my_port, conn->peer_port,
        conn->peer_qp, psn, psn + 1, opcode, reth
    );
    if(pcap_sendpacket(conn->handle, (uint8_t *)frame, size) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(conn->handle));
    }

}

static void send_roce_ack(int port, int psn){
    connection_t *conn = conns+port;
    uint8_t frame[2048];
    int size = build_eth_packet(
        frame, PACKET_TYPE_ACK, NULL, 0,
        conn->my_mac, conn->peer_mac,
        conn->my_ip, conn->peer_ip,
        conn->my_port, conn->peer_port,
        conn->peer_qp, psn, psn + 1, 0x11, NULL
    );
    if(pcap_sendpacket(conn->handle, (uint8_t *)frame, size) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(conn->handle));
    }

}

/**
 * simulation of p4 switch
 */
void pipeline(metadata_t *meta_p, const struct pcap_pkthdr *pkthdr, const uint8_t *packet) {

    // parser: extract header info

    eth_header_t* eth = (eth_header_t*)packet;
    ipv4_header_t* ip = (ipv4_header_t*)(packet + sizeof(eth_header_t));
    udp_header_t* udp = (udp_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t));
    bth_header_t* bth = (bth_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t));
    meta_p->psn = ntohl(bth->apsn) & 0x00FFFFFF; 
    meta_p->opcode = bth->opcode;
    switch(bth->opcode){
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x04:
        case 0x07: // write middle
        case 0x08: // write last
            if(meta_p->ingress_port < FAN_IN){
                meta_p->type = UP_DATA;
            }
            else{
                meta_p->type = DOWN_DATA;
            }
            break;
        case 0x06:
        case 0x0A:
            if(meta_p->ingress_port < FAN_IN){
                meta_p->type = UP_WRITE_FIRST_ONLY;
            }
            else{
                meta_p->type = DOWN_WRITE_FIRST_ONLY;
            }
            break;
        case 0x11:
            if(meta_p->ingress_port < FAN_IN){
                meta_p->type = UP_ACK;
            } 
            else{
                meta_p->type = DOWN_ACK;
            }
            break;
    }

    // control: table match and action
    if(meta_p->type == UP_DATA){
        uint32_t* data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4); // icrc = 4
        assert(data_len == PAYLOAD_LEN);
        degree[Idx(meta_p->psn)]+=1;
        if(root){
            if(recv_from_port(meta_p->ingress_port, meta_p->psn)){
                if(recv_from_port(FAN_IN, meta_p->psn)){ // has recieved from parent, just forward to the port
                    send_roce_data(meta_p->ingress_port, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }
            }
            else{ // first transmission
                set_arrive_state(meta_p->ingress_port, meta_p->psn);

                for(int i=0;i<data_len/sizeof(int);++i){
                    aggregator[Idx(meta_p->psn)][i] += ntohl(data[i]);
                }

                if(recv_from_all_fan_in(meta_p->psn)){
                    set_arrive_state(FAN_IN, meta_p->psn);
                    clear_state_data(meta_p->psn + WINDOW_SIZE);
                    // broadcast
                    for(int i=0;i<FAN_IN;++i){
                        send_roce_data(i, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                    }
                }

            }
        }
        else{
            if(recv_from_port(meta_p->ingress_port, meta_p->psn)){ // retransmission
                if(recv_from_port(FAN_IN, meta_p->psn)){ // has recieved from parent, just forward to the port
                    send_roce_data(meta_p->ingress_port, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }
                else{   // under this condition, all child can't get the result packet, so all fan in will retransmit packets.
                    if(recv_from_all_fan_in(meta_p->psn) && degree[Idx(meta_p->psn)]%FAN_IN==0){
                        send_roce_data(FAN_IN, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                    }
                }
            }
            else{ // first transmission
                set_arrive_state(meta_p->ingress_port, meta_p->psn);

                for(int i=0;i<data_len/sizeof(int);++i){
                    aggregator[Idx(meta_p->psn)][i] += ntohl(data[i]);
                }

                if(recv_from_all_fan_in(meta_p->psn)){
                    // forward to parent
                    send_roce_data(FAN_IN, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }

            }
        }

    }
    else if(meta_p->type == UP_ACK){
        // ack reflection
        send_roce_ack(meta_p->ingress_port, meta_p->psn);

    }
    else if(meta_p->type == DOWN_DATA){
        uint32_t* data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4); // icrc = 4
        assert(data_len == PAYLOAD_LEN);
        if(!recv_from_port(FAN_IN, meta_p->psn) && recv_from_all_fan_in(meta_p->psn)){ // the second condition is very important! see 6.24 draft.
            memcpy(aggregator[Idx(meta_p->psn)], data, PAYLOAD_LEN);
            set_arrive_state(FAN_IN,meta_p->psn);
            // broadcast()
            for(int i=0;i<FAN_IN;++i){
                send_roce_data(i, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
            }
        }
        else {
            return; // just ignore, very rare
        }
    }
    else if(meta_p->type == DOWN_ACK){
        // impossible
    }
    else if(meta_p->type == UP_WRITE_FIRST_ONLY){
        uint32_t *data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t) + sizeof(reth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(reth_header_t) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4); // icrc = 4
        assert(data_len == PAYLOAD_LEN);
        degree[Idx(meta_p->psn)]+=1;
        char *reth = (char *)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));

        if(root){
            if(recv_from_port(meta_p->ingress_port, meta_p->psn)){
                if(recv_from_port(FAN_IN, meta_p->psn)){ // has recieved from parent (as for root, it means aggregation completed), just forward to the port
                    send_roce_data_with_reth(meta_p->ingress_port, (uint8_t *)(&(reth_keeper[Idx(meta_p->psn)][meta_p->ingress_port])), (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }
            }
            else{ // first transmission
                set_arrive_state(meta_p->ingress_port, meta_p->psn);
                memcpy(&(reth_keeper[Idx(meta_p->psn)][meta_p->ingress_port]), reth, sizeof(reth_header_t));
                for(int i=0;i<data_len/sizeof(int);++i){
                    aggregator[Idx(meta_p->psn)][i] += ntohl(data[i]);
                }

                if(recv_from_all_fan_in(meta_p->psn)){
                    set_arrive_state(FAN_IN, meta_p->psn);
                    clear_state_data(meta_p->psn + WINDOW_SIZE);
                    // broadcast
                    for(int i=0;i<FAN_IN;++i){
                        send_roce_data_with_reth(i, (uint8_t *)(&(reth_keeper[Idx(meta_p->psn)][i])), (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                    }
                }
            }
        }
        else{
            if(recv_from_port(meta_p->ingress_port, meta_p->psn)){ // retransmission
                if(recv_from_port(FAN_IN, meta_p->psn)){ // has recieved from parent, just forward to the port
                    send_roce_data_with_reth(meta_p->ingress_port, (uint8_t *)(&(reth_keeper[Idx(meta_p->psn)][meta_p->ingress_port])), (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }
                else{   // under this condition, all child can't get the result packet, so all fan in will retransmit packets.
                    if(recv_from_all_fan_in(meta_p->psn) && degree[Idx(meta_p->psn)]%FAN_IN==0){
                        send_roce_data_with_reth(FAN_IN, NULL, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                    }
                }
            }
            else{ // first transmission
                set_arrive_state(meta_p->ingress_port, meta_p->psn);
                memcpy(&(reth_keeper[Idx(meta_p->psn)][meta_p->ingress_port]), reth, sizeof(reth_header_t));

                for(int i=0;i<data_len/sizeof(int);++i){
                    aggregator[Idx(meta_p->psn)][i] += ntohl(data[i]);
                }

                if(recv_from_all_fan_in(meta_p->psn)){
                    // forward to parent
                    send_roce_data_with_reth(FAN_IN, NULL, (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
                }

            }
        }
    }
    else if(meta_p->type == DOWN_WRITE_FIRST_ONLY){
         uint32_t *data = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t) + sizeof(reth_header_t));
        int data_len = (ntohs(udp->length) - sizeof(reth_header_t) - sizeof(bth_header_t) - sizeof(udp_header_t) - 4); // icrc = 4
        assert(data_len == PAYLOAD_LEN);
        if(!recv_from_port(FAN_IN, meta_p->psn) && recv_from_all_fan_in(meta_p->psn)){ // the second condition is very important! see 6.24 draft.
            memcpy(aggregator[Idx(meta_p->psn)], data, PAYLOAD_LEN);
            set_arrive_state(FAN_IN,meta_p->psn);
            // broadcast()
            for(int i=0;i<FAN_IN;++i){
                send_roce_data_with_reth(i, (uint8_t *)(&(reth_keeper[Idx(meta_p->psn)][i])), (uint8_t *)aggregator[Idx(meta_p->psn)], meta_p->psn, PAYLOAD_LEN, meta_p->opcode);
            }
        }
        else {
            return; // just ignore, very rare
        }
    }

}


/**
 * port
 * epoll from all ports and process the packets one by one, in one thread 
 * */
void epoll_process_packets(){

    const unsigned char *packet;
    struct pcap_pkthdr *pkthdr;
    
    while (true) {
        struct epoll_event events[MAX_EVENTS];
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            metadata_t meta;
            meta.ingress_port = events[i].data.u32;
            
            while ((pcap_next_ex(conns[meta.ingress_port].handle, &pkthdr, &packet)) == 1) {
                printf("recv packet from port %d\n",meta.ingress_port);
                pipeline(&meta, pkthdr, packet);
            }
        }
    }
}

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

    init_topology(controller_ip);
    printf("init finish");
    
    epoll_process_packets();
    
    return 0;
}