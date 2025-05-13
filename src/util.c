#include "util.h"
#include "api.h"
#include "log.h"

uint32_t get_ip(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
        log_write(-1, "Invalid IP address: %s\n", ip_str);
        return 0;
    }
    return addr.s_addr;
}

void print_packet(const my_packet_t *p) {
    printf("===============================================\n");
    if (!p) {
        printf("Packet is NULL!\n");
        return;
    }

    printf("Packet Header:\n");
    printf("  seq:  %u (0x%08X)\n", p->header.seq, p->header.seq);
    printf("  type: %u (0x%08X)\n", p->header.type, p->header.type);

    printf("Packet Payload:\n");
    for (int i = 0; i < PAYLOAD_LEN; i++) {
        printf("  payload[%d]: %d (0x%08X)\n", i, (p->payload[i]), p->payload[i]);
    }
    printf("===============================================\n");
}

// 打印 MAC 地址
void print_mac(int id, const char *prefix, const uint8_t mac[6]) {
    log_write(id, "%s%02X:%02X:%02X:%02X:%02X:%02X\n", prefix,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 打印 IP 地址
void print_ip(int id, const char *prefix, uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    log_write(id, "%s%s\n", prefix, inet_ntoa(addr));
}

// 打印以太网头
void print_eth_header(int id, const eth_header_t *eth) {
    log_write(id, "==== Ethernet Header ====\n");
    print_mac(id, "  Destination MAC: ", eth->dst_mac);
    print_mac(id, "  Source MAC:      ", eth->src_mac);
    log_write(id, "  EtherType:       0x%04X\n", ntohs(eth->ether_type));
}

// 打印 IPv4 头
void print_ipv4_header(int id, const ipv4_header_t *ip) {
    log_write(id, "==== IPv4 Header ====\n");
    log_write(id, "  Version:         %u\n", ip->version_ihl >> 4);
    log_write(id, "  IHL:             %u (words)\n", ip->version_ihl & 0x0F);
    log_write(id, "  TOS:             0x%02X\n", ip->tos);
    log_write(id, "  Total Length:    %u bytes\n", ntohs(ip->total_length));
    log_write(id, "  ID:              0x%04X\n", ntohs(ip->id));
    log_write(id, "  Flags:           %s%s%s\n",
           (ntohs(ip->flags_frag_off) & 0x8000) ? "[Reserved] " : "",
           (ntohs(ip->flags_frag_off) & 0x4000) ? "[DF] " : "",
           (ntohs(ip->flags_frag_off) & 0x2000) ? "[MF] " : "");
    log_write(id, "  Fragment Offset: %u\n", ntohs(ip->flags_frag_off) & 0x1FFF);
    log_write(id, "  TTL:             %u\n", ip->ttl);
    log_write(id, "  Protocol:        %u (UDP=17)\n", ip->protocol);
    log_write(id, "  Checksum:        0x%04X\n", ntohs(ip->checksum));
    print_ip(id, "  Source IP:       ", ip->src_ip);
    print_ip(id, "  Destination IP:  ", ip->dst_ip);
}

// 打印 UDP 头
void print_udp_header(int id, const udp_header_t *udp) {
    log_write(id, "==== UDP Header ====\n");
    log_write(id, "  Source Port:     %u\n", ntohs(udp->src_port));
    log_write(id, "  Destination Port:%u\n", ntohs(udp->dst_port));
    log_write(id, "  Length:          %u bytes\n", ntohs(udp->length));
    log_write(id, "  Checksum:        0x%04X\n", ntohs(udp->checksum));
}

// 打印 RRoCE BTH 头
void print_bth_header(int id, const bth_header_t *bth) {
    log_write(id, "==== RRoCE BTH Header ====\n");
    log_write(id, "  Opcode:          0x%02X\n", bth->opcode);
    log_write(id, "  SE/M/Pad:        0x%02X\n", bth->se_m_pad);
    log_write(id, "  PKey:            0x%04X\n", ntohs(bth->pkey));
    log_write(id, "  QPN:             %u\n", ntohl(bth->qpn) & 0x00FFFFFF);
    log_write(id, "  APSN:            %u\n", ntohl(bth->apsn) & 0x00FFFFFF);
}

void print_connection(int id, const connection_t *conn) {
    log_write(id, "==== Connection Info ====\n");
    log_write(id, "  Device:           %s\n", conn->device);
    print_mac(id, "  My MAC:           ", conn->my_mac);
    print_mac(id, "  Peer MAC:         ", conn->peer_mac);
    print_ip(id, "  My IP:            ", conn->my_ip);
    print_ip(id, "  Peer IP:          ", conn->peer_ip);
    log_write(id, "  My Port:          %u\n", conn->my_port);
    log_write(id, "  Peer Port:        %u\n", conn->peer_port);
    log_write(id, "  My QP:            %u\n", conn->my_qp);
    log_write(id, "  Peer QP:          %u\n", conn->peer_qp);
    log_write(id, "  PSN:              %u\n", conn->psn);
}

uint16_t ipv4_checksum(const ipv4_header_t *ip) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)ip;
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4; // IPv4 头长度（字节）
    uint16_t saved_checksum = ip->checksum;     // 保存原始 checksum
    ((ipv4_header_t *)ip)->checksum = 0;


    // 逐 16-bit 累加
    for (size_t i = 0; i < ihl / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // 处理溢出（进位加到低 16 位）
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    ((ipv4_header_t *)ip)->checksum = saved_checksum;
    // 返回反码
    return htons((uint16_t)(~sum));
}

int is_ipv4_checksum_valid(const ipv4_header_t *ip) {
    // 如果 checksum 为 0，表示未启用校验（如 offload 场景）
    // if (ip->checksum == 0) {
    //     return 1; // 跳过校验
    // }

    // 计算并比对
    uint16_t computed = ipv4_checksum(ip);
    return (computed == ntohs(ip->checksum));
}


#define POLY 0xEDB88320
uint32_t crc32_table[8][256];  // 8 个表，每个 256 项

void init_crc32_table() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (crc & 1 ? POLY : 0);
        }
        crc32_table[0][i] = crc;
    }

    // 派生后面的7张表
    for (int t = 1; t < 8; t++) {
        for (int i = 0; i < 256; i++) {
            crc32_table[t][i] = (crc32_table[t - 1][i] >> 8) ^ crc32_table[0][crc32_table[t - 1][i] & 0xFF];
        }
    }
}
uint32_t crc32(const void *data, size_t length) {
    const uint8_t *buf = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;

    // 处理按8字节对齐的数据块
    while (length >= 8) {
        uint8_t b0 = buf[0] ^ (crc & 0xFF);
        uint8_t b1 = buf[1] ^ ((crc >> 8) & 0xFF);
        uint8_t b2 = buf[2] ^ ((crc >> 16) & 0xFF);
        uint8_t b3 = buf[3] ^ ((crc >> 24) & 0xFF);
        uint8_t b4 = buf[4];
        uint8_t b5 = buf[5];
        uint8_t b6 = buf[6];
        uint8_t b7 = buf[7];

        crc =
            crc32_table[0][b7] ^
            crc32_table[1][b6] ^
            crc32_table[2][b5] ^
            crc32_table[3][b4] ^
            crc32_table[4][b3] ^
            crc32_table[5][b2] ^
            crc32_table[6][b1] ^
            crc32_table[7][b0];

        buf += 8;
        length -= 8;
    }

    // 处理剩余的字节
    while (length--) {
        crc = (crc >> 8) ^ crc32_table[0][(crc ^ *buf++) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}



// uint32_t crc32_table[256];

// void init_crc32_table() {
//     for (uint32_t i = 0; i < 256; i++) {
//         uint32_t c = i;
//         for (int j = 0; j < 8; j++) {
//             if (c & 1) {
//                 c = (c >> 1) ^ 0xEDB88320;
//             } else {
//                 c = c >> 1;
//             }
//         }
//         crc32_table[i] = c;
//     }
// }
// uint32_t crc32(const void *data, size_t length) {
//     const uint8_t *bytes = (const uint8_t *)data;
//     uint32_t crc = 0xFFFFFFFF;

//     for (size_t i = 0; i < length; i++) {
//         uint8_t index = (crc ^ bytes[i]) & 0xFF;
//         crc = (crc >> 8) ^ crc32_table[index];
//     }

//     return crc ^ 0xFFFFFFFF;
// }


// uint32_t crc32(const void *data, size_t length) {
//     const uint8_t *bytes = (const uint8_t *)data;
//     uint32_t crc = 0xFFFFFFFF;  // 初始值
    
//     for (size_t i = 0; i < length; i++) {
//         crc ^= bytes[i];  // 与当前字节异或
        
//         // 处理每个字节的8位
//         for (int j = 0; j < 8; j++) {
//             if (crc & 1) {
//                 // 如果最低位是1，右移并与多项式异或
//                 crc = (crc >> 1) ^ 0xEDB88320;
//             } else {
//                 // 否则只右移
//                 crc = crc >> 1;
//             }
//         }
//     }
    
//     return crc ^ 0xFFFFFFFF;  // 最终异或
// }

// 计算 RoCEv2 ICRC
uint32_t compute_icrc(int id, const char* eth_packet) {
    // clock_t start = clock();
    ipv4_header_t* iip = (ipv4_header_t*)(eth_packet + sizeof(eth_header_t));
    int len = ntohs(iip->total_length) - 4; // 减去 icrc

    char pack[5555];
    memcpy(pack + 8, eth_packet + sizeof(eth_header_t), len);
    len += 8;
    for(int i = 0; i < 8; i++) {
        pack[i] = 0xFF;
    }
        
    ipv4_header_t* ip = (ipv4_header_t*)(pack + 8);
    udp_header_t* udp = (udp_header_t*)(pack + 8 + sizeof(ipv4_header_t));
    bth_header_t* bth = (bth_header_t*)(pack + 8 + sizeof(ipv4_header_t) + sizeof(udp_header_t));

    ip->tos = ip->tos | 0xFF;
    ip->ttl = ip->ttl | 0xFF;
    ip->checksum = ip->checksum | 0xFFFF;
    udp->checksum = udp->checksum | 0xFFFF;
    bth->qpn = bth->qpn | 0x000000FF;

    // printf("crc ***********************************\n");
    // for(int i = 0; i < len; i++) {
    //     printf("%02x ", (unsigned char)pack[i]);
    // }
    // printf("\n");
    // printf("crc ***********************************\n");

    // uint32_t tmp = crc32(pack, len);
    // clock_t end = clock();

    // double elapsed_time = (double)(end - start) / CLOCKS_PER_SEC;
    // printf("%s, Time taken: %f seconds\n", "build eth pack", elapsed_time);
    // return tmp;
    return crc32(pack, len);
}

int is_icrc_valid(int id, const char* packet) {
    uint32_t* icrc = (uint32_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t) + ICCL_HEADER_LEN + sizeof(my_packet_t));

    uint32_t mycrc = compute_icrc(id, packet);

    log_write(id, "icrc: 0x%08X, mycrc: 0x%08X\n", *icrc, mycrc);
}


void print_all(int id, const char* packet) {
    LOG_FUNC_ENTRY(id);
    log_write(id, "==== bits ====\n");
    int len = 0;
    len += sizeof(eth_header_t);
    len += sizeof(ipv4_header_t);
    len += sizeof(udp_header_t);
    len += sizeof(bth_header_t);
    len += sizeof(my_packet_t);
    len += 4;
    // for(int i = 0; i < len; i++) {
    //     printf("%02x ", (unsigned char)packet[i]);
    // }
    printf("\n");
    log_write(id, "\n");
    print_eth_header(id, (eth_header_t*)packet);
    print_ipv4_header(id, (ipv4_header_t*)(packet + sizeof(eth_header_t)));
    print_udp_header(id, (udp_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t)));
    print_bth_header(id, (bth_header_t*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t)));

    if(is_ipv4_checksum_valid((ipv4_header_t*)(packet + sizeof(eth_header_t)))) {
        log_write(id, "valid...\n");
    } else {
        log_write(id, "not valid...\n");
    }

    // Packet* mypack = (Packet*)(packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t) + ICCL_HEADER_LEN);
    // print_packet(mypack);

    is_icrc_valid(id, packet);
    log_write(id, "\n\n\n\n");
    LOG_FUNC_EXIT(id);
}

uint32_t build_eth_packet
(
    char *dst_packet, int type, char *data, int data_len, 
    char *src_mac, char *dst_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t qp, uint32_t psn, 
    uint32_t msn, int packet_type
) {
    // clock_t start = clock();
    uint16_t total_len = sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t) + data_len + 4; // 4 为icrc
    if(type == PACKET_TYPE_ACK || type == PACKET_TYPE_NAK)
        total_len += sizeof(aeth_t);

    // 1. eth hdr
    eth_header_t* eth = (eth_header_t*)dst_packet;
    memcpy(eth->src_mac, src_mac, 6);
    memcpy(eth->dst_mac, dst_mac, 6);
    eth->ether_type = htons(0x0800);

    // 2. ip hdr
    ipv4_header_t* ip = (ipv4_header_t*)(dst_packet + sizeof(eth_header_t));
    ip->version_ihl = 0x45;
    ip->tos = 0x00;
    ip->total_length = htons(total_len - sizeof(eth_header_t));
    ip->id = 0x1111; // 应该没用这里
    ip->flags_frag_off = htons(0x4000);
    ip->ttl = 0x40;
    ip->protocol = 0x11; // udp
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->checksum = ipv4_checksum(ip);

    // 3. udp hdr
    udp_header_t* udp = (udp_header_t*)(dst_packet + sizeof(eth_header_t) + sizeof(ipv4_header_t));
    udp->src_port = htons(src_port);
    // udp->src_port = htons(0x5b25);
    udp->dst_port = htons(dst_port);
    udp->length = htons(total_len - sizeof(eth_header_t) - sizeof(ipv4_header_t));
    udp->checksum = 0x0000;


    // 4. bth hdr
    bth_header_t* bth = (bth_header_t*)(dst_packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t));
    if(type == PACKET_TYPE_DATA)
        bth->opcode = packet_type;
    else
        bth->opcode = 0x11;
    bth->se_m_pad = 0x00;
    bth->pkey = 0xffff;
    bth->qpn = htonl(qp & 0x00FFFFFF);
    if(type == PACKET_TYPE_DATA)
        bth->apsn = htonl(psn | 0x80000000); // ack request
    else
        bth->apsn = htonl(psn);

    // 5. aeth
    if(type == PACKET_TYPE_ACK || type == PACKET_TYPE_NAK){
        aeth_t* aeth = (aeth_t*)(dst_packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        if(type == PACKET_TYPE_ACK)
            aeth->syn_msn = htonl(msn | 0x1f000000);
        else if(type == PACKET_TYPE_NAK)
            aeth->syn_msn = htonl(msn | 0x60000000); //高8位: 0110 0000 => psn seq error
    }

    // 6. data
    if(type == PACKET_TYPE_DATA) {
        unsigned char* d = (unsigned char*)(dst_packet + sizeof(eth_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t) + sizeof(bth_header_t));
        // memcpy(d, data, data_len);
        for(int i = 0; i < data_len / 4; i++) {
            ((uint32_t*)d)[i] = (((uint32_t*)data)[i]);
        }
    }

    // 7. icrc
    uint32_t* icrc = (uint32_t*)(dst_packet + total_len - 4);
    *icrc = compute_icrc(-1, dst_packet);

    // if(type == PACKET_TYPE_ACK || type == PACKET_TYPE_NAK) {
    //     printf("========= ack =========\n");
    //     for(int i = 0; i < total_len; i++) {
    //         printf("%02x ", (unsigned char)dst_packet[i]);
    //     }
    //     printf("\n%d\n", total_len);
    //     printf("========= ack =========\n");
    // }
    
    // clock_t end = clock();

    // double elapsed_time = (double)(end - start) / CLOCKS_PER_SEC;
    // printf("%s, type: %d, Time taken: %f seconds\n", "build eth pack", type, elapsed_time);
    return total_len;
}

uint64_t get_now_ts() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    // printf("Timestamp (milliseconds): %lld\n", milliseconds);
    return milliseconds;
}