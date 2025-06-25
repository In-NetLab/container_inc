#include "api.h"
#include "util.h"
#include <assert.h>
#include "topo_parser.h"

// 模拟上层应用数据
#define IN_DATA_COUNT 10240
int32_t in_data[IN_DATA_COUNT];
int32_t dst_data[IN_DATA_COUNT];

#define PACKET_NUM IN_DATA_COUNT / PAYLOAD_COUNT
#define WINDOW_SIZE_IN_4096 2

clock_t start_time;

void print_cost_time(const char * prefix) {
    clock_t end = clock();

    double elapsed_time = (double)(end - start_time) / CLOCKS_PER_SEC;
    printf("%s, Time taken: %f mileseconds\n", prefix, elapsed_time * 1000);
}

void init_data_to_aggregate(int rank) {     
    
    for(int i = 0; i < IN_DATA_COUNT; i++) {
        in_data[i] = i * (rank+1);
    }
}

int post_send(struct inccl_communicator *comm, int32_t* src_data, int id) {
    struct ibv_send_wr sr;
    struct ibv_sge send_sge;
    struct ibv_send_wr *send_bad_wr;

    int *send_payload = (int *)(comm->send_payload + id * PAYLOAD_COUNT * sizeof(int32_t));

    for(int i=0;i<PAYLOAD_COUNT;++i){
        send_payload[i] = htonl((src_data + id * PAYLOAD_COUNT)[i]);
    }
    
    //memcpy(send_payload, src_data + id * PAYLOAD_COUNT, PAYLOAD_COUNT * sizeof(uint32_t));

    memset(&send_sge, 0, sizeof(send_sge));
    send_sge.addr = (uintptr_t)(comm->send_payload + id * PAYLOAD_COUNT * sizeof(int32_t));
    send_sge.length = PAYLOAD_COUNT * sizeof(int32_t);
    send_sge.lkey = comm->mr_send_payload->lkey;
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = id;
    sr.sg_list = &send_sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_SEND ;
    // only to check the ack reflection, no use
    sr.send_flags = IBV_SEND_SIGNALED;
    return ibv_post_send(comm->qp, &sr, &send_bad_wr);
}


void allreduce(struct inccl_communicator *comm, int32_t* src_data, int len, int32_t* dst_data) {
    int receive_num = 0;
    int send_num = 0;
    int packet_num = len / PAYLOAD_COUNT;

    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;

    struct ibv_recv_wr rr;
    struct ibv_sge receive_sge;
    struct ibv_recv_wr *receive_bad_wr;

    // post receive
    for(int i = 0; i < packet_num; i++) {
        memset(&receive_sge, 0, sizeof(receive_sge));
        receive_sge.addr = (uintptr_t)(comm->receive_payload + i * PAYLOAD_COUNT * sizeof(int32_t));
        receive_sge.length = PAYLOAD_COUNT * sizeof(int32_t);
        receive_sge.lkey = comm->mr_receive_payload->lkey;
        memset(&rr, 0, sizeof(rr));
        rr.next = NULL;
        rr.wr_id = i;
        rr.sg_list = &receive_sge;
        rr.num_sge = 1;
        int ret = ibv_post_recv(comm->qp, &rr, &receive_bad_wr);
        printf("i: %d, post recv ret %d\n", i, ret);
    }

    // post send
    for(int i = 0; i < WINDOW_SIZE_IN_4096; i++) {
        post_send(comm, src_data, i);
        send_num++;
    }

    // using poll, which will be replaced by event + poll
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc)*PACKET_NUM);
    while(receive_num != packet_num) {
        int result = ibv_poll_cq(comm->cq, PACKET_NUM, wc);
        if(result > 0) {
            // printf("\n");
            for(int i = 0; i < result; i++){
                struct ibv_wc *tmp = wc + i;
                // printf("tmp->status %d\n", tmp->status);
                // printf("tmp->opcode %d\n", tmp->opcode);

                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV) {
                    printf("receive success\n");

                    uint64_t id = tmp->wr_id;
                    int *pack = (int *)(comm->receive_payload + id * PAYLOAD_COUNT * sizeof(int32_t));

                    for(int j = 0; j <PAYLOAD_COUNT; ++j){
                        (dst_data + receive_num * PAYLOAD_COUNT)[j] = ntohl(pack[j]);
                    }

                    //memcpy(dst_data + receive_num * PAYLOAD_COUNT, pack, PAYLOAD_COUNT * sizeof(int32_t));
                    receive_num++;

                    if(send_num < packet_num) {
                        post_send(comm, src_data, send_num);
                        send_num++;
                    }
                } else if(tmp->status==IBV_WC_SUCCESS) {
                    printf("send success\n");
                    // if(send_num < packet_num) {
                    //     post_send(comm, src_data, send_num);
                    //     send_num++;
                    // }
                } else {
                    printf("what???? wc status: %d, opcode: %d\n", tmp->status, tmp->opcode);
                }

            }
        }
    }
}


int main(int argc, char *argv[]) {
    if(argc != 4) {
        printf("need 3 params now\n");
    }

    int world_size = atoi(argv[1]);
    char *master_addr = argv[2];
    int rank = atoi(argv[3]);

    init_data_to_aggregate(rank);

    struct inccl_group *group = inccl_group_create(world_size,rank,master_addr); // group_id=0

    struct inccl_communicator *comm = inccl_communicator_create(group, IN_DATA_COUNT * 4);
    printf("start...\n");

    start_time = clock();

    allreduce(comm, in_data, IN_DATA_COUNT, dst_data);
    print_cost_time("over");
    
    for(int i = 0; i < IN_DATA_COUNT; i++) {
        assert(dst_data[i] == 3 * i);
        // if(i < 516)
            //printf("idx: %d, in data: %d, reduce data: %d\n", i, in_data[i], dst_data[i]);
    }
    printf("result ok\n");

    return 0;
}