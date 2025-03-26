#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define TCP_PORT 31324 // March 1st 3:24 :)
#define ICCL_HEADER_LEN 8
#define GID_IDX 1
// used for debug

struct iccl_group{
    uint32_t peer_ip;
    int sock_fd;                           //TCP socket file descriptor
    int payload_mtu; // minus header length
    int local_ib_port; // 1 in default
    int local_gid_idx; // 1 in default
    bool local_gender; // 1 client, 0 server 
    struct ibv_device_attr local_device_attr; // Device attributes 
    struct ibv_port_attr local_port_attr;     // IB port attributes 
    struct ibv_context *local_ib_ctx;         // device handle
};

/* mtu and psn are in default */
struct iccl_connection_info{
    //char *addr;
    //uint32_t rkey;
    uint16_t lid;
    uint32_t qp_num;
    union ibv_gid gid;
}__attribute__((packed));

struct iccl_communicator{
    struct iccl_group *group;
    uint32_t payload_buf_size; // need to up round, mod payload_mtu
    char iccl_header[ICCL_HEADER_LEN]; // first bytes in buffer
    char *send_payload; // following bytes in buffer
    char *receive_payload;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr_send_payload;
    struct ibv_mr *mr_receive_payload;
    struct ibv_mr *mr_iccl_header;
    // peer info
    uint16_t peer_lid;
    uint32_t peer_qp_num;
    union ibv_gid peer_gid;
};

struct iccl_group *iccl_group_create(int group_id);
int iccl_group_destroy(struct iccl_group *group);

struct iccl_communicator *iccl_communicator_create(struct iccl_group *group, uint32_t size);
int iccl_communicator_destroy(struct iccl_communicator *comm);

int iccl_allreduce(struct iccl_communicator *comm, void *src_addr, void *dst_addr, uint32_t size, int type, int opcode);
