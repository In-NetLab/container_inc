#include "api.h"


// 模拟上层应用数据
#define IN_DATA_LEN 1024
int32_t in_data[IN_DATA_LEN];
int32_t dst_data[IN_DATA_LEN];

#define PACKET_NUM IN_DATA_LEN / PAYLOAD_SIZE
#define WINDOW_SIZE 1

// 记录每个packet到达状态
// 0 未发送; 1 已发送; 2已ack
int flag[PACKET_NUM];
bool send_flag;
pthread_mutex_t flag_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t send_cond = PTHREAD_COND_INITIALIZER;
int start;

int cnt = 0;

void init_all(int group_id) {
    // 初始化上层应用数据
    for(int i = 0; i < IN_DATA_LEN; i++) {
        in_data[i] = i * group_id;
    }
    memset(flag, 0, sizeof(flag));
    send_flag = true;
    start = 0;
}


void allreduce(struct iccl_communicator *comm, int32_t* src_data, int len, int32_t* dst_data) {
    int receive_num = 0;
    int packet_num = len / PAYLOAD_SIZE;

    struct ibv_recv_wr rr;
    struct ibv_sge receive_sge_list[2];
    struct ibv_recv_wr *receive_bad_wr;
    receive_sge_list[0].addr = (uintptr_t)comm->iccl_header;
    receive_sge_list[0].length = ICCL_HEADER_LEN;
    receive_sge_list[0].lkey = comm->mr_iccl_header->lkey;

    for(int i = 0; i < WINDOW_SIZE; i++) {
        // post receive
        memset(&receive_sge_list[1], 0, sizeof(receive_sge_list[1]));
        receive_sge_list[1].addr = (uintptr_t)(comm->receive_payload + i * sizeof(Packet));
        receive_sge_list[1].length = sizeof(Packet);
        receive_sge_list[1].lkey = comm->mr_receive_payload->lkey;
        memset(&rr, 0, sizeof(rr));
        rr.next = NULL;
        rr.wr_id = i;
        rr.sg_list = receive_sge_list;
        rr.num_sge = 2;
        int ret = ibv_post_recv(comm->qp, &rr, &receive_bad_wr);
        printf("post recv ret %d\n", ret);

        Packet packet;
        packet.header.seq = i;
        packet.header.type = PACKET_TYPE_DATA;
        for(int j = 0; j < PAYLOAD_SIZE; j++) {
            packet.payload[j] = src_data[i * PAYLOAD_SIZE + j];
        }
        Packet *send_payload = (Packet *)(comm->send_payload + (i % WINDOW_SIZE) * sizeof(Packet));
        send_payload->header.seq = htonl(packet.header.seq);
        send_payload->header.type = htonl(packet.header.type);
        for(int i = 0; i < PAYLOAD_SIZE; i++) {
            send_payload->payload[i] = htonl(packet.payload[i]);
        }

        struct ibv_qp_attr attr;
        struct ibv_qp_init_attr init_attr;
        
        // post send
        struct ibv_send_wr sr;
        struct ibv_sge send_sge_list[2];
        struct ibv_send_wr *send_bad_wr;
        send_sge_list[0].addr = (uintptr_t)comm->iccl_header;
        send_sge_list[0].length = ICCL_HEADER_LEN;
        send_sge_list[0].lkey = comm->mr_iccl_header->lkey;
        memset(&send_sge_list[1], 0, sizeof(send_sge_list[1]));
        send_sge_list[1].addr = (uintptr_t)(comm->send_payload + (i % WINDOW_SIZE) * sizeof(Packet));
        send_sge_list[1].length = sizeof(Packet);
        send_sge_list[1].lkey = comm->mr_send_payload->lkey;
        memset(&sr, 0, sizeof(sr));
        sr.next = NULL;
        sr.wr_id = i;
        sr.sg_list = send_sge_list;
        sr.num_sge = 2;
        sr.opcode = IBV_WR_SEND ;
        // only to check the ack reflection, no use
        sr.send_flags = IBV_SEND_SIGNALED;
        ret = ibv_post_send(comm->qp, &sr, &send_bad_wr);
        printf("group %d post send ret %d\n", comm->group->group_id, ret);
        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
        printf("after send QP state: %d\n", attr.qp_state);
    }
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;
    ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
    printf("QP state: %d\n", attr.qp_state);
    printf("post recv over...=======================\n");


    // using poll, which will be replaced by event + poll
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc)*PACKET_NUM);
    while(receive_num != packet_num) {
        int result = ibv_poll_cq(comm->cq, PACKET_NUM, wc);
        if(result > 0) {
            printf("\n");
            struct ibv_qp_attr attr;
            struct ibv_qp_init_attr init_attr;
            ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
            printf("QP state: %d\n", attr.qp_state);
            for(int i = 0; i < result; i++){
                printf("result %d\n", result);
                struct ibv_wc *tmp = wc+i;
                printf("tmp->status %d\n", tmp->status);
                printf("tmp->opcode %d\n", tmp->opcode);

                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV){
                    printf("receive success\n");
                    receive_num++;
                    uint64_t id = tmp->wr_id;
                    Packet *pack = (Packet *)(comm->receive_payload + (id % WINDOW_SIZE) * sizeof(Packet));
                    print_packet(pack);

                    // 解包
                    uint32_t psn = cnt;
                    uint32_t type = ntohl(pack->header.type);

                    pthread_mutex_lock(&flag_mutex);
                    flag[psn] = 2;

                    // post receive
                    if(receive_num < packet_num) {
                        memset(&receive_sge_list[1], 0, sizeof(receive_sge_list[1]));
                        receive_sge_list[1].addr = (uintptr_t)(comm->receive_payload + (receive_num % WINDOW_SIZE) * sizeof(Packet));
                        receive_sge_list[1].length = sizeof(Packet);
                        receive_sge_list[1].lkey = comm->mr_receive_payload->lkey;
                        memset(&rr, 0, sizeof(rr));
                        rr.next = NULL;
                        rr.wr_id = receive_num;
                        rr.sg_list = receive_sge_list;
                        rr.num_sge = 2;
                        int ret = ibv_post_recv(comm->qp, &rr, &receive_bad_wr);
                        printf("post recv ret %d\n", ret);
                        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
                        printf("after post receive QP state: %d\n", attr.qp_state);
                        cnt++;

                        Packet packet;
                        packet.header.seq = cnt;
                        packet.header.type = PACKET_TYPE_DATA;
                        for(int j = 0; j < PAYLOAD_SIZE; j++) {
                            packet.payload[j] = src_data[cnt * PAYLOAD_SIZE + j];
                        }
                        Packet *send_payload = (Packet *)(comm->send_payload + (cnt % WINDOW_SIZE) * sizeof(Packet));
                        send_payload->header.seq = htonl(packet.header.seq);
                        send_payload->header.type = htonl(packet.header.type);
                        for(int k = 0; k < PAYLOAD_SIZE; k++) {
                            send_payload->payload[k] = htonl(packet.payload[k]);
                        }
                
                        struct ibv_qp_attr attr;
                        struct ibv_qp_init_attr init_attr;
                        
                        // post send
                        struct ibv_send_wr sr;
                        struct ibv_sge send_sge_list[2];
                        struct ibv_send_wr *send_bad_wr;
                        send_sge_list[0].addr = (uintptr_t)comm->iccl_header;
                        send_sge_list[0].length = ICCL_HEADER_LEN;
                        send_sge_list[0].lkey = comm->mr_iccl_header->lkey;
                        memset(&send_sge_list[1], 0, sizeof(send_sge_list[1]));
                        send_sge_list[1].addr = (uintptr_t)(comm->send_payload + (cnt % WINDOW_SIZE) * sizeof(Packet));
                        send_sge_list[1].length = sizeof(Packet);
                        send_sge_list[1].lkey = comm->mr_send_payload->lkey;
                        memset(&sr, 0, sizeof(sr));
                        sr.next = NULL;
                        sr.wr_id = cnt;
                        sr.sg_list = send_sge_list;
                        sr.num_sge = 2;
                        sr.opcode = IBV_WR_SEND ;
                        // only to check the ack reflection, no use
                        sr.send_flags = IBV_SEND_SIGNALED;
                        ret = ibv_post_send(comm->qp, &sr, &send_bad_wr);
                        printf("group %d post send ret %d\n", comm->group->group_id, ret);
                        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
                        printf("after send QP state: %d\n", attr.qp_state);
                    }

                    pthread_mutex_unlock(&flag_mutex);
                    
                    for(int i = 0; i < PAYLOAD_SIZE; i++) {
                        dst_data[psn * PAYLOAD_SIZE + i] = ntohl(pack->payload[i]);
                    }
                }else if(tmp->status==IBV_WC_SUCCESS){
                    printf("other success\n");
                }else {
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
    // client
    gender = 0;             
    ip_p = "10.50.183.171"; 

    init_all(id);

    struct iccl_group *group = iccl_group_create(id); // group_id=0

    uint32_t data_size = 64;
    struct iccl_communicator *comm = iccl_communicator_create(group, data_size);
    // for(int i = 0; i < 1;i++) {
    //     printf("sleep %d\n", i);
    //     sleep(1);
    // }
    printf("start...\n");

    allreduce(comm, in_data, IN_DATA_LEN, dst_data);
    
    for(int i = 0; i < IN_DATA_LEN; i++) {
        printf("idx: %d, in data: %d, reduce data: %d\n", i, in_data[i], dst_data[i]);
    }

    return 0;
}