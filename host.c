#include "api.h"

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("need 1 params now\n");
    }
    int id = atoi(argv[1]);
    // client
    gender = 0;          
    ip_p = "10.50.183.171"; 

    struct iccl_group *group = iccl_group_create(id); // group_id=0

    uint32_t data_size = 64;
    struct iccl_communicator *comm = iccl_communicator_create(group, data_size);
    sleep(10);
    printf("start...\n");

    Packet packet;
    packet.header.seq = 0;
    packet.header.type = PACKET_TYPE_DATA;
    for(int i = 0; i < PAYLOAD_SIZE; i++) {
        packet.payload[i] = i * id;
    }

    int dst_data[16];
    
    comm->iccl_header[0] = 0;
    int *dst_addr_int = (int *)dst_data;
    Packet *send_payload = (Packet *)comm->send_payload;
    send_payload->header.seq = htonl(packet.header.seq);
    send_payload->header.type = htonl(packet.header.type);
    for(int i = 0; i < PAYLOAD_SIZE; i++) {
        send_payload->payload[i] = htonl(packet.payload[i]);
    }

    struct ibv_recv_wr rr;
    struct ibv_sge receive_sge_list[2];
    struct ibv_recv_wr *receive_bad_wr;
    receive_sge_list[0].addr = (uintptr_t)comm->iccl_header;
    receive_sge_list[0].length = ICCL_HEADER_LEN;
    receive_sge_list[0].lkey = comm->mr_iccl_header->lkey;

    struct ibv_send_wr sr;
    struct ibv_sge send_sge_list[2];
    struct ibv_send_wr *send_bad_wr;
    send_sge_list[0].addr = (uintptr_t)comm->iccl_header;
    send_sge_list[0].length = ICCL_HEADER_LEN;
    send_sge_list[0].lkey = comm->mr_iccl_header->lkey;

    int psn;
    int size = sizeof(Packet);
    for(psn = 0; psn < 1; psn++) {
        struct ibv_qp_attr attr;
        struct ibv_qp_init_attr init_attr;
        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
        printf("    1QP state: %d\n", attr.qp_state);

        // post receive
        memset(&receive_sge_list[1], 0, sizeof(receive_sge_list[1]));
        receive_sge_list[1].addr = (uintptr_t)comm->receive_payload + psn * size;
        receive_sge_list[1].length = size;
        receive_sge_list[1].lkey = comm->mr_receive_payload->lkey;
        memset(&rr, 0, sizeof(rr));
        rr.next = NULL;
        rr.wr_id = psn;
        rr.sg_list = receive_sge_list;
        rr.num_sge = 2;
        int ret = ibv_post_recv(comm->qp, &rr, &receive_bad_wr);
        printf("post recv ret %d\n", ret);
        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
        printf("    2QP state: %d\n", attr.qp_state);
        
        // post send
        memset(&send_sge_list[1], 0, sizeof(send_sge_list[1]));
        send_sge_list[1].addr = (uintptr_t)comm->send_payload + psn * size;
        send_sge_list[1].length = size;
        send_sge_list[1].lkey = comm->mr_send_payload->lkey;

        memset(&sr, 0, sizeof(sr));
        sr.next = NULL;
        sr.wr_id = psn;
        sr.sg_list = send_sge_list;
        sr.num_sge = 2;
        sr.opcode = IBV_WR_SEND ;
        // only to check the ack reflection, no use
        sr.send_flags = IBV_SEND_SIGNALED;
        ret = ibv_post_send(comm->qp, &sr, &send_bad_wr);
        printf("post send ret %d\n", ret);
        ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
        printf("    3QP state: %d\n", attr.qp_state);
    }

    // using poll, which will be replaced by event + poll
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc)*psn);
    int accum=0, result=0;
    do
    {
        result = ibv_poll_cq(comm->cq, psn, wc);
        //accum+=result;
        if(result>0){
            struct ibv_qp_attr attr;
            struct ibv_qp_init_attr init_attr;
            ibv_query_qp(comm->qp, &attr, IBV_QP_STATE, &init_attr);
            printf("QP state: %d\n", attr.qp_state);
            for(int i=0; i<result;++i){
                printf("result %d\n", result);
                struct ibv_wc *tmp = wc+i;
                printf("tmp->status %d\n", tmp->status);
                printf("tmp->opcode %d\n", tmp->opcode);

                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV){
                    printf("receive success\n");
                    accum += 1;
                    uint64_t id = tmp->wr_id;
                    Packet *pack = (Packet *)((uintptr_t)comm->receive_payload + id * size);
                    print_packet(pack);

                    // 解包
                    uint32_t psn = ntohl(pack->header.seq);
                    uint32_t type = ntohl(pack->header.type);
                }else if(tmp->status==IBV_WC_SUCCESS){
                    printf("    hh\n");
                    accum+=1;
                }
                printf("    hhh\n");
            }
        }
    }while(accum != 2*psn);

    return 0;
}