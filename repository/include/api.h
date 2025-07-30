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
#include "parameter.h"
#include "topo_parser.h"
/**
 * 所有进程（包括Rank 0）都需要提前知道通信组的进程总数（world_size）​​
 * 且​​非Rank 0的进程需要知道Rank 0的IP地址和端口​​来建立初始连接
 * 
 * 控制器的ip地址被配置到每一个主机的环境变量中。
 * 
 * 也就是说，控制器ip是最先知道的，
 * 然后通过某种方式将rank放置到不同的节点上并通过程序的参数传入rank的信息（可能有一个启动节点，比如slurm里提交任务的节点，这个启动节点不同于控制节点），
 * 这样能够实现解耦
 *  */ 

#define TCP_PORT_1 31324 // March 1st 3:24 :)
#define TCP_PORT_2 31325

#define INCCL_HEADER_LEN 8
#define GID_IDX 1

#define WINDOW_SIZE 8192 //in bytes
#define MESSAGE_SIZE (4 * (PAYLOAD_LEN)) // tradeoff between window shift efficiency and the overhead of posting send 
#define PAYLOAD_COUNT ((MESSAGE_SIZE) / (sizeof(int))) // 元素个数

struct inccl_group{
    // group info
    int group_id; // only for rank0
    int rank;
    int world_size;

    union{
        const char *controller_ip;
        const char *master_ip;
    };

    union{
        int controller_fd; // for rank0
        int master_fd; // for others
    };

    int *group_fd_list; // size is world_size, for rank0 to broadcast info

    // local info
    union ibv_gid local_gid;
    // int payload_mtu; // minus header length
    int local_ib_port; // 1 in default
    int local_gid_idx; // 1 in default
    struct ibv_device_attr local_device_attr; // Device attributes 
    struct ibv_port_attr local_port_attr;     // IB port attributes 
    struct ibv_context *local_ib_ctx;         // device handle
    

};

/* info sent t0 master or controller, no use*/
struct inccl_rank_exchange_info{
    int rank;
    uint32_t ip;
}__attribute__((packed));


struct inccl_communicator{
    struct inccl_group *group;
    uint32_t payload_buf_size; // need to up round, mod payload_mtu
    uint32_t window_size; // need to reach an agreement with switch
    // char inccl_header[inccl_HEADER_LEN]; // first bytes in buffer
    char *send_payload; // following bytes in buffer
    char *receive_payload;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr_send_payload;
    struct ibv_mr *mr_receive_payload;
};

struct inccl_group *inccl_group_create(int world_size, int rank, const char * master_ip);
int inccl_group_destroy(struct inccl_group *group);

struct inccl_communicator *inccl_communicator_create(struct inccl_group *group, uint32_t size);
int inccl_communicator_destroy(struct inccl_communicator *comm);

void inccl_allreduce_sendrecv(struct inccl_communicator *comm, int32_t* src_data, uint32_t len, int32_t* dst_data);

void inccl_allreduce_write(struct inccl_communicator *comm, int32_t* src_data, uint32_t len, int32_t* dst_data);