#ifndef UTIL_H
#define UTIL_H


#include <stdint.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pcap.h>

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} eth_header_t;

// IPv4 头 20 bytes
typedef struct {
    uint8_t  version_ihl;    // 版本 (4 bits) + IHL (4 bits)
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag_off; // 标志 (3 bits) + 分片偏移 (13 bits)
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_header_t;

// UDP 头 8 bytes
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length; // 总长
    uint16_t checksum;
} udp_header_t;

// RRoCE (RoCEv2) BTH 头 12bytes
typedef struct {
    uint8_t  opcode;
    uint8_t  se_m_pad;
    uint16_t pkey;
    uint32_t qpn;
    uint32_t apsn;
} bth_header_t;

// AETH 4 bytes
typedef struct {
    uint32_t syn_msn; // syndrome + msn
} aeth_t;

typedef struct {
	uint64_t va;
	uint32_t rkey;
	uint32_t len;
} reth_header_t;


typedef struct {
    char device[16]; // 网卡设备名

    uint8_t  my_mac[6];
    uint8_t  peer_mac[6];
    uint32_t my_ip;
    uint32_t peer_ip;
    uint16_t my_port;
    uint16_t peer_port;

    uint32_t my_qp;
    uint32_t peer_qp;
    uint32_t psn;
    uint32_t msn;

    int ok;

    pcap_t *handle;
} connection_t;

#define PACKET_TYPE_DATA 0
#define PACKET_TYPE_ACK 1
#define PACKET_TYPE_NAK 2
#define PACKET_TYPE_DATA_SINGLE 3
#define PACKET_TYPE_RETH 4

#define PAYLOAD_LEN 1024 // mtu bytes
#define ELEMENT_SIZE sizeof(int32_t)

typedef struct {
    uint32_t seq;
    uint32_t type;
    // ...
} my_header_t;

typedef int32_t my_payload_t[PAYLOAD_LEN];

typedef struct  {
    my_header_t header;
    my_payload_t payload;
} my_packet_t; 

void print_packet(const my_packet_t *p);

uint32_t get_ip(const char *ip_str);

void print_mac(int id, const char *prefix, const uint8_t mac[6]);
void print_ip(int id, const char *prefix, uint32_t ip);
void print_eth_header(int id, const eth_header_t *eth);
void print_ipv4_header(int id, const ipv4_header_t *ip);
void print_udp_header(int id, const udp_header_t *udp);
void print_bth_header(int id, const bth_header_t *bth);
void print_connection(int id, const connection_t *conn);

uint16_t ipv4_checksum(const ipv4_header_t *ip);
int is_ipv4_checksum_valid(const ipv4_header_t *ip);
uint32_t crc32(const void *data, size_t length);
uint32_t compute_icrc(int id, const char* packet);
int is_icrc_valid(int id, const char* packet);
void print_all(int id, const char* packet);

uint32_t build_eth_packet
(
    char *dst_packet, int type, char *data, int data_len, 
    char *src_mac, char *dst_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t qp, uint32_t psn, 
    uint32_t msn, int packet_type, const uint8_t *reth
);

uint64_t get_now_ts();

void init_crc32_table();
uint32_t crc32(const void *data, size_t length);

void send_file_with_length(int fd, const char *file_path) ;
void receive_file(int sockfd, const char *save_path) ;

#endif // UTIL_H

