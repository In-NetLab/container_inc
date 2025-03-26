#include "api.h"

// static void print_wc(const struct ibv_wc *wc) {
//     printf("wr_id: 0x%lx\n", wc->wr_id);
//     printf("status: %d\n", wc->status);
//     printf("opcode: %d\n", wc->opcode);
//     printf("vendor_err: 0x%x\n", wc->vendor_err);
//     printf("byte_len: %u\n", wc->byte_len);
    
//     if (wc->wc_flags & IBV_WC_WITH_IMM) {
//         printf("imm_data: 0x%x\n", wc->imm_data);
//     }
//     if (wc->wc_flags & IBV_WC_WITH_INV) {
//         printf("invalidated_rkey: 0x%x\n", wc->invalidated_rkey);
//     }
    
//     printf("qp_num: %u\n", wc->qp_num);
//     printf("src_qp: %u\n", wc->src_qp);
//     printf("wc_flags: 0x%x\n", wc->wc_flags);
//     printf("pkey_index: %u\n", wc->pkey_index);
//     printf("slid: %u\n", wc->slid);
//     printf("sl: %u\n", wc->sl);
//     printf("dlid_path_bits: %u\n", wc->dlid_path_bits);
// }


/* gotten ip and gender from controller, but controller isn't determined 
    success 1, fail 0 */
static int iccl_group_subscribe(struct iccl_group *group){
    inet_pton(AF_INET, ip_p,&group->peer_ip);
    group->local_gender = gender;
    return 1;
}

/* success 1, fail 0, socket will be written in group */
// static int iccl_group_socket_connect(struct iccl_group *group){
//     return 0;
// }

/* don't forget to modify the gender */
struct iccl_group *iccl_group_create(int group_id){
    struct iccl_group *group = (struct iccl_group *)malloc(sizeof(struct iccl_group));
    group->local_ib_port = 1;
    group->local_gid_idx = 1;
    // init local ib device 
    struct ibv_device **dev_list = NULL;
    int num_devices;
    dev_list = ibv_get_device_list(&num_devices);
    //debug
    printf("devices num %d\n",num_devices);
    for(int i = 0; i < num_devices; i ++)
    {
        printf("%s\n",ibv_get_device_name(dev_list[i]));
    }
    //group->local_ib_ctx = ibv_open_device(dev_list[4]);
    group->local_ib_ctx = ibv_open_device(dev_list[gender]);
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ibv_query_device(group->local_ib_ctx, &group->local_device_attr);
    ibv_query_port(group->local_ib_ctx, group->local_ib_port, &group->local_port_attr);

    group->payload_mtu = (1<<(group->local_port_attr.active_mtu + 7))-ICCL_HEADER_LEN;
    // subscribe to controller to get peer ip and gender
    iccl_group_subscribe(group);

    // connect to peer in tcp
    if(group->local_gender==0){
        // client
        group->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(TCP_PORT);
        server_addr.sin_addr.s_addr = group->peer_ip;
        while(connect(group->sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) continue;
        printf("success conn\n");
    } else{
        int server_fd;
        struct sockaddr_in server_addr, client_addr;
        socklen_t addr_len = sizeof(client_addr);
        server_fd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(TCP_PORT);
        bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        listen(server_fd, 1);
        group->sock_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        close(server_fd);
        printf("success conn\n");
    }

    return group;
}



int iccl_group_destroy(struct iccl_group *group);


// exchange
static int iccl_sock_sync(int sock_fd, uint32_t size, char *send_addr, char *receive_addr){
    if(size==0){
        char sync;
        write(sock_fd, "s", 1);
        read(sock_fd, &sync, 1);
        return 0;
    }
    else{
        int read_bytes = 0;
        int total_read_bytes = 0;
        write(sock_fd, send_addr, size);

        while(total_read_bytes < size)
        {
            read_bytes = read(sock_fd, receive_addr, size);
            if(read_bytes > 0)
            {
                total_read_bytes += read_bytes;
            }
            else break;
        }
    }
    return 0;
}

struct iccl_communicator *iccl_communicator_create(struct iccl_group *group, uint32_t size){
    struct iccl_communicator *comm = (struct iccl_communicator *)malloc(sizeof(struct iccl_communicator));
    comm->group = group;
    
    comm->pd = ibv_alloc_pd(group->local_ib_ctx);

    
    int segment_num = (size+group->payload_mtu-1)/(group->payload_mtu);
    printf("segment_num: %d\n",segment_num);
    comm->payload_buf_size = segment_num * group->payload_mtu;
    printf("payload_buf_size: %d\n",comm->payload_buf_size);
    comm->cq = ibv_create_cq(group->local_ib_ctx, segment_num, NULL, NULL,0);
    // mr
    comm->send_payload = (char *)malloc(comm->payload_buf_size);
    comm->receive_payload = (char *)malloc(comm->payload_buf_size);

    memset(comm->send_payload, 0 , comm->payload_buf_size);
    memset(comm->receive_payload, 0 , comm->payload_buf_size);

    memset(comm->iccl_header, 0, ICCL_HEADER_LEN);
    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE ;
    comm->mr_send_payload = ibv_reg_mr(comm->pd, comm->send_payload, comm->payload_buf_size, mr_flags);
    comm->mr_receive_payload = ibv_reg_mr(comm->pd, comm->receive_payload, comm->payload_buf_size, mr_flags);

    comm->mr_iccl_header = ibv_reg_mr(comm->pd, comm->iccl_header, ICCL_HEADER_LEN, mr_flags);
    // qp create
    struct ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = comm->cq;
    qp_init_attr.recv_cq = comm->cq;
    qp_init_attr.cap.max_send_wr = segment_num;
    qp_init_attr.cap.max_recv_wr = segment_num;
    qp_init_attr.cap.max_send_sge = 2;
    qp_init_attr.cap.max_recv_sge = 2;
    comm->qp = ibv_create_qp(comm->pd, &qp_init_attr);
    // connect qp
    struct iccl_connection_info local_info;
    struct iccl_connection_info peer_info;
    // fill in the local_info
    union ibv_gid my_gid;
    ibv_query_gid(group->local_ib_ctx, group->local_ib_port, GID_IDX, &my_gid);
    local_info.gid = my_gid;
    local_info.lid = htons(group->local_port_attr.lid);
    local_info.qp_num = htonl(comm->qp->qp_num); // big end in connection
    // peer info
    iccl_sock_sync(group->sock_fd, sizeof(struct iccl_connection_info), (char *)&local_info, (char *)&peer_info);
    comm->peer_gid = peer_info.gid;
    comm->peer_qp_num = ntohl(peer_info.qp_num);
    comm->peer_lid = ntohs(peer_info.lid);
    fprintf(stdout, "Remote QP number = 0x%x\n", comm->peer_qp_num);
    fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                comm->peer_gid.raw[0], comm->peer_gid.raw[1], comm->peer_gid.raw[2], comm->peer_gid.raw[3], comm->peer_gid.raw[4], comm->peer_gid.raw[5], comm->peer_gid.raw[6], comm->peer_gid.raw[7], comm->peer_gid.raw[8], comm->peer_gid.raw[9], comm->peer_gid.raw[10], comm->peer_gid.raw[11], comm->peer_gid.raw[12], comm->peer_gid.raw[13], comm->peer_gid.raw[14], comm->peer_gid.raw[15]);
    // qp attr
    struct ibv_qp_attr attr;
    int qp_flags;
    // qp to init
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = group->local_ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    qp_flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    int ret = ibv_modify_qp(comm->qp, &attr, qp_flags);
    //printf("ret of init %d\n",ret);
    // qp to rtr
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = group->local_port_attr.active_mtu;
    attr.dest_qp_num = comm->qp->qp_num; //debug
    //attr.dest_qp_num = comm->peer_qp_num; //debug
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.dlid = comm->peer_lid;

    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.is_global = 1;
    attr.ah_attr.port_num = group->local_ib_port;
    //attr.ah_attr.grh.dgid = comm->peer_gid;
    attr.ah_attr.grh.dgid = my_gid;

    attr.ah_attr.grh.hop_limit = 1; // in example it is 1, why?
    attr.ah_attr.grh.sgid_index = group->local_gid_idx;
    attr.ah_attr.grh.flow_label = 0;
    attr.ah_attr.grh.traffic_class = 0;
    qp_flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    ret = ibv_modify_qp(comm->qp, &attr, qp_flags);
    //modify_qp_to_rtr(comm->qp,attr.dest_qp_num,0,&comm->peer_gid);
    printf("ret of rtr %d\n",ret);
    //printf("qp status: %d\n",comm->qp->state);
    // qp to rts
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    qp_flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    ret = ibv_modify_qp(comm->qp, &attr, qp_flags);
    printf("ret of rts %d\n",ret);
    return comm;
}


int iccl_communicator_destroy(struct iccl_communicator *comm);

/*  user need to fill in the comm's buffer ahead.
    size is smaller than bufsize 
    depend on the type to convert to the big end
    depend on the opcode to set the iccl_header of com

    only implement "+"" and "int" by 3.3
    */
int iccl_allreduce(struct iccl_communicator *comm, void *src_addr, void *dst_addr, uint32_t size, int type, int opcode){
    // iccl header default 0 means "+"
    comm->iccl_header[0] = 0;
    int *src_addr_int = (int *)src_addr;
    int *dst_addr_int = (int *)dst_addr;
    int *send_payload_int = (int *)comm->send_payload;
    
    for(int i = 0; i<size/sizeof(int); ++i){
        send_payload_int[i] = htonl(src_addr_int[i]);
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
    int seq = 0;
    for(int i_addr = 0; i_addr < size; i_addr+=comm->group->payload_mtu, seq+=1){
        // post receive
        memset(&receive_sge_list[1], 0, sizeof(receive_sge_list[1]));
        receive_sge_list[1].addr = (uintptr_t)comm->receive_payload + seq * comm->group->payload_mtu;
        //receive_sge_list[1].length = comm->group->payload_mtu;
        receive_sge_list[1].length = size;
        receive_sge_list[1].lkey = comm->mr_receive_payload->lkey;

        memset(&rr, 0, sizeof(rr));
        rr.next = NULL;
        rr.wr_id = seq;
        rr.sg_list = receive_sge_list;
        rr.num_sge = 2;

        //if(gender) 
        {
            int ret = ibv_post_recv(comm->qp, &rr, &receive_bad_wr);
            printf("post recv ret %d\n", ret);
        }
        
        // post send
        memset(&send_sge_list[1], 0, sizeof(send_sge_list[1]));
        send_sge_list[1].addr = (uintptr_t)comm->send_payload + seq * comm->group->payload_mtu;
        send_sge_list[1].length = size;
        //send_sge_list[1].length = comm->group->payload_mtu;
        send_sge_list[1].lkey = comm->mr_send_payload->lkey;
        printf("comm->mr_send_payload->lkey %d\n", comm->mr_send_payload->lkey);

        memset(&sr, 0, sizeof(sr));
        sr.next = NULL;
        sr.wr_id = seq;
        sr.sg_list = send_sge_list;
        sr.num_sge = 2;
        sr.opcode = IBV_WR_SEND ;
        // only to check the ack reflection, no use
        sr.send_flags = IBV_SEND_SIGNALED;
        //if(!gender)
        {
            int ret = ibv_post_send(comm->qp, &sr, &send_bad_wr);
            printf("post send ret %d\n", ret);
        }
    }

    // using poll, which will be replaced by event + poll
    printf("seq %d\n", seq);
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc)*seq);
    int accum=0, result=0;
    printf("qp status: %d\n",comm->qp->state);
    do
    {
        result = ibv_poll_cq(comm->cq, seq, wc);
        //accum+=result;
        if(result>0){
            printf("qp status: %d\n",comm->qp->state);
            for(int i=0; i<result;++i){
                printf("result %d\n", result);
                struct ibv_wc *tmp = wc+i;
                printf("tmp->status %d\n", tmp->status);
                printf("tmp->opcode %d\n", tmp->opcode);
                //print_wc(tmp);
                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV){
                    accum+=1;
                    uint64_t id = tmp->wr_id;
                    int *receive_tmp = (int *)((uintptr_t)comm->receive_payload + id * comm->group->payload_mtu);
                    for(int j = 0;j<comm->group->payload_mtu/sizeof(int);++j){
                        dst_addr_int[j] = ntohl(receive_tmp[j]);
                    }
                }else if(tmp->status==IBV_WC_SUCCESS){
                    accum+=1;
                }
                // else{
                //     int ret = ibv_post_send(comm->qp, &sr, &send_bad_wr);
                //     printf("post send ret %d\n", ret); 
                //     if(ret) goto exit;
                // }
            }
        }
    }
    while(accum != 2*seq);
    //while(accum >= seq);
    printf("qp status: %d\n",comm->qp->state);
    return 0;

}