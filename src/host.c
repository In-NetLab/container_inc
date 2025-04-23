#include "api.h"
#include "util.h"
#include <assert.h>

// 模拟上层应用数据
#define IN_DATA_LEN 1024000
int32_t in_data[IN_DATA_LEN];
int32_t dst_data[IN_DATA_LEN];

#define PACKET_NUM IN_DATA_LEN / PAYLOAD_SIZE
#define WINDOW_SIZE 1

clock_t start_time;

void print_cost_time(const char * prefix) {
    clock_t end = clock();

    double elapsed_time = (double)(end - start_time) / CLOCKS_PER_SEC;
    printf("%s, Time taken: %f seconds\n", prefix, elapsed_time);
}

void init_all(int group_id) {
    // client
    gender = 0;             
    ip_p = "10.50.183.69"; 
    // 初始化上层应用数据
    for(int i = 0; i < IN_DATA_LEN; i++) {
        in_data[i] = i * group_id;
    }
}

int post_send(struct iccl_communicator *comm, int32_t* src_data, int id) {
    struct ibv_send_wr sr;
    struct ibv_sge send_sge;
    struct ibv_send_wr *send_bad_wr;

    my_packet_t packet;
    packet.header.seq = id;
    packet.header.type = PACKET_TYPE_DATA;
    memcpy(packet.payload, src_data + id * PAYLOAD_SIZE, PAYLOAD_SIZE * 4);
    my_packet_t *send_payload = (my_packet_t *)(comm->send_payload + id * sizeof(my_packet_t));
    send_payload->header.seq = htonl(packet.header.seq);
    send_payload->header.type = htonl(packet.header.type);
    for(int i = 0; i < PAYLOAD_SIZE; i++) {
        send_payload->payload[i] = htonl(packet.payload[i]);
    }

    
    memset(&send_sge, 0, sizeof(send_sge));
    send_sge.addr = (uintptr_t)(comm->send_payload + id * sizeof(my_packet_t));
    send_sge.length = sizeof(my_packet_t);
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


void allreduce(struct iccl_communicator *comm, int32_t* src_data, int len, int32_t* dst_data) {
    int receive_num = 0;
    int send_num = 0;
    int packet_num = len / PAYLOAD_SIZE;

    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;

    struct ibv_recv_wr rr;
    struct ibv_sge receive_sge;
    struct ibv_recv_wr *receive_bad_wr;

    // post receive
    for(int i = 0; i < packet_num; i++) {
        memset(&receive_sge, 0, sizeof(receive_sge));
        receive_sge.addr = (uintptr_t)(comm->receive_payload + i * sizeof(my_packet_t));
        receive_sge.length = sizeof(my_packet_t);
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
    for(int i = 0; i < WINDOW_SIZE; i++) {
        post_send(comm, src_data, i);
        send_num++;
    }

    // using poll, which will be replaced by event + poll
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc)*PACKET_NUM);
    while(receive_num != packet_num) {
        int result = ibv_poll_cq(comm->cq, PACKET_NUM, wc);
        if(result > 0) {
            printf("\n");
            for(int i = 0; i < result; i++){
                struct ibv_wc *tmp = wc + i;
                printf("tmp->status %d\n", tmp->status);
                printf("tmp->opcode %d\n", tmp->opcode);

                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV) {
                    printf("receive success\n");

                    uint64_t id = tmp->wr_id;
                    my_packet_t *pack = (my_packet_t *)(comm->receive_payload + id * sizeof(my_packet_t));
                    for(int j = 0; j < PAYLOAD_SIZE; j++) {
                        dst_data[receive_num * PAYLOAD_SIZE + j] = ntohl(pack->payload[j]);
                    }
                    receive_num++;

                    if(send_num < packet_num) {
                        post_send(comm, src_data, send_num);
                        send_num++;
                    }
                } else if(tmp->status==IBV_WC_SUCCESS) {
                    printf("send success\n");
                } else {
                    printf("what????????????????????????????\n");
                }

            }
        }
    }
}


int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("need 1 params now\n");
    }
    int id = atoi(argv[1]);

    init_all(id);

    struct iccl_group *group = iccl_group_create(id); // group_id=0

    struct iccl_communicator *comm = iccl_communicator_create(group, IN_DATA_LEN * 4 * 2);
    printf("start...\n");

    
    start_time = clock();

    allreduce(comm, in_data, IN_DATA_LEN, dst_data);
    print_cost_time("over");
    
    for(int i = 0; i < IN_DATA_LEN; i++) {
        assert(dst_data[i] == 3 * i);
        // if(i < 516)
            //printf("idx: %d, in data: %d, reduce data: %d\n", i, in_data[i], dst_data[i]);
    }
    printf("result ok\n");

    return 0;
}