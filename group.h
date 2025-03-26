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
#include "flow.h"


struct iccl_group{

    uint16_t group_id; // allocated by controller, within the scope of the cluster
    uint16_t rank;   // allocated by controller
    uint64_t mem_resource; // in switch, the max memory to use, same as the send window
    int recv_ratio;
    int device_idx; // specified by controller
    
    uint32_t payload_mtu;
    // set message size default to packet size.
    uint64_t message_size; // cut data to messages, and messages are cut to packets by rdma.
    int local_ib_port; // 1 in default
    int local_gid_idx; // 1 in default
    struct ibv_device_attr local_device_attr; // Device attributes 
    struct ibv_port_attr local_port_attr;     // IB port attributes 
    struct ibv_context *local_ib_ctx;         // device handle

    struct iccl_ring_mr_buffer send_window;
    struct iccl_ring_mr_buffer recv_window;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;

    // because of the pseudo peer qp, the peer qp doesn't matter
    uint16_t peer_lid; // zero
    uint32_t peer_qp_num; // !! can we use this field to specify the rank and the group id ?  
    union ibv_gid peer_gid; // can we use a broadcast address or the controller's ip?

};


struct iccl_group *iccl_group_create();
int iccl_group_init(struct iccl_group *group);
int iccl_group_destroy(struct iccl_group *group);