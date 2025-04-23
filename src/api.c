#include "api.h"

// used for debug
int gender;
char *ip_p;
/* gotten ip and gender from controller, but controller isn't determined 
    success 1, fail 0 */
static int iccl_group_subscribe(struct iccl_group *group){
    inet_pton(AF_INET, ip_p,&group->peer_ip);
    group->local_gender = gender;
    return 1;
}

/* don't forget to modify the gender */
struct iccl_group *iccl_group_create(int group_id){
    struct iccl_group *group = (struct iccl_group *)malloc(sizeof(struct iccl_group));
    group->group_id = group_id;
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
    
    group->local_ib_ctx = ibv_open_device(dev_list[0]);
    
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ibv_query_device(group->local_ib_ctx, &group->local_device_attr);
    ibv_query_port(group->local_ib_ctx, group->local_ib_port, &group->local_port_attr);

    // group->payload_mtu = (2<<(group->local_port_attr.active_mtu + 7))-ICCL_HEADER_LEN;
    // printf("group payload mtu: %d\n", group->payload_mtu);
    // subscribe to controller to get peer ip and gender
    iccl_group_subscribe(group);

    return group;
}



int iccl_group_destroy(struct iccl_group *group) {
    printf("destory...\n");
    return 1;
}

struct iccl_communicator *iccl_communicator_create(struct iccl_group *group, uint32_t size){
    struct iccl_communicator *comm = (struct iccl_communicator *)malloc(sizeof(struct iccl_communicator));
    comm->group = group;
    
    comm->pd = ibv_alloc_pd(group->local_ib_ctx);

    
    int segment_num = size / 1024 / 4;
    printf("segment_num: %d\n",segment_num);
    comm->payload_buf_size = size * 2;
    printf("payload_buf_size: %d\n",comm->payload_buf_size);
    comm->cq = ibv_create_cq(group->local_ib_ctx, segment_num, NULL, NULL,0);
    // mr
    comm->send_payload = (char *)malloc(sizeof(char)*comm->payload_buf_size);
    comm->receive_payload = (char *)malloc(sizeof(char)*comm->payload_buf_size);

    memset(comm->send_payload, 0 , comm->payload_buf_size);
    memset(comm->receive_payload, 0 , comm->payload_buf_size);

    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE ;
    comm->mr_send_payload = ibv_reg_mr(comm->pd, comm->send_payload, comm->payload_buf_size, mr_flags);
    comm->mr_receive_payload = ibv_reg_mr(comm->pd, comm->receive_payload, comm->payload_buf_size, mr_flags);

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
    
    comm->peer_gid = my_gid;
    uint8_t* ip = (uint8_t*)&group->peer_ip;
    for(int i = 12; i < 16; i++) {
        comm->peer_gid.raw[i] = ip[i-12];
    }
    comm->peer_qp_num = 27 + group->group_id;
    comm->peer_lid = 0;
    fprintf(stdout, "My QP number = 0x%x\n", comm->qp->qp_num);
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
    printf("ret of init %d\n",ret);
    // qp to rtr
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = group->local_port_attr.active_mtu;
    attr.dest_qp_num = comm->peer_qp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.dlid = comm->peer_lid;

    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.is_global = 1;
    attr.ah_attr.port_num = group->local_ib_port;
    attr.ah_attr.grh.dgid = comm->peer_gid;
    attr.ah_attr.grh.hop_limit = 64; // in example it is 1, why?
    attr.ah_attr.grh.sgid_index = group->local_gid_idx;
    attr.ah_attr.grh.flow_label = 0;
    attr.ah_attr.grh.traffic_class = 0;
    qp_flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    ret = ibv_modify_qp(comm->qp, &attr, qp_flags);
    //modify_qp_to_rtr(comm->qp,attr.dest_qp_num,0,&comm->peer_gid);
    printf("ret of rtr %d\n",ret);
    printf("qp status: %d\n",comm->qp->state);
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
