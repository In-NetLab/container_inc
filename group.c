#include "group.h"

// subscribe to the controller
struct iccl_group *iccl_group_create(){
    struct iccl_group *group = (struct iccl_group *)malloc(sizeof(struct iccl_group));
    
    // get info allocated by controller
    group->group_id = 0;
    group->rank = 0;
    group->mem_resource = 1024;
    group->device_idx = 0;
    group->local_ib_port = 1;
    group->local_gid_idx = 1;
    group->recv_ratio = 4;
    //group->message_size = group->payload_mtu; // default to mtu, a message is a packet.
    return group;
}

int iccl_group_init(struct iccl_group *group){
    
    // init local ib device 
    struct ibv_device **dev_list = NULL;
    int num_devices;
    dev_list = ibv_get_device_list(&num_devices);
    printf("devices num %d\n",num_devices); //debug
    group->local_ib_ctx = ibv_open_device(dev_list[0]);
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ibv_query_device(group->local_ib_ctx, &group->local_device_attr);
    ibv_query_port(group->local_ib_ctx, group->local_ib_port, &group->local_port_attr);
    group->payload_mtu = 1<<(group->local_port_attr.active_mtu + 7);
    group->message_size = group->payload_mtu; // default to mtu, a message is a packet.

    group->pd = ibv_alloc_pd(group->local_ib_ctx);
    int mr_number = (group->mem_resource)/(group->message_size);
    group->send_window.buffer = (char *)calloc(group->mem_resource,sizeof(char));
    group->recv_window.buffer = (char *)calloc(group->mem_resource * group->recv_ratio, sizeof(char));
    // may receive twice of window because of receive and send process not same rate, for 2 stages of switch.
    group->cq = ibv_create_cq(group->local_ib_ctx, mr_number * group->recv_ratio, NULL, NULL,0);

    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE ;
    group->send_window.mr = ibv_reg_mr(group->pd, group->send_window.buffer, group->mem_resource, mr_flags);
    group->recv_window.mr = ibv_reg_mr(group->pd, group->recv_window.buffer, group->mem_resource * group->recv_ratio, mr_flags);
    group->send_window.avail_size = group->mem_resource;
    group->send_window.avail_pos = 0;
    group->send_window.capacity = group->mem_resource;
    group->recv_window.avail_size = group->mem_resource * group->recv_ratio;
    group->recv_window.avail_pos = 0;
    group->recv_window.capacity = group->mem_resource * group->recv_ratio;
    // qp create
    struct ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = group->cq;
    qp_init_attr.recv_cq = group->cq;
    qp_init_attr.cap.max_send_wr = mr_number;
    qp_init_attr.cap.max_recv_wr = mr_number * group->recv_ratio;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    group->qp = ibv_create_qp(group->pd, &qp_init_attr);
    // fill in the local_info
    union ibv_gid my_gid;
    ibv_query_gid(group->local_ib_ctx, group->local_ib_port, group->local_gid_idx, &my_gid);

    group->peer_gid = my_gid; // how to set the pseudo peer gid???
    group->peer_gid.raw[15] = 1;
    group->peer_qp_num = ntohl(group->group_id) + 10;
    group->peer_lid = 0;
    fprintf(stdout, "Remote QP number = 0x%x\n", group->peer_qp_num);
    fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                group->peer_gid.raw[0], group->peer_gid.raw[1], group->peer_gid.raw[2], group->peer_gid.raw[3], group->peer_gid.raw[4], group->peer_gid.raw[5], group->peer_gid.raw[6], group->peer_gid.raw[7], group->peer_gid.raw[8], group->peer_gid.raw[9], group->peer_gid.raw[10], group->peer_gid.raw[11], group->peer_gid.raw[12], group->peer_gid.raw[13], group->peer_gid.raw[14], group->peer_gid.raw[15]);
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
    int ret = ibv_modify_qp(group->qp, &attr, qp_flags);
    if(ret){
        printf("ret of init %d\n",ret);
        return -1;
    }
    // qp to rtr
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = group->local_port_attr.active_mtu;
    //attr.dest_qp_num = group->peer_qp_num;
    attr.dest_qp_num = 4;

    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.dlid = group->peer_lid;

    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.is_global = 1;
    attr.ah_attr.port_num = group->local_ib_port;
    attr.ah_attr.grh.dgid = group->peer_gid;
    //attr.ah_attr.grh.dgid = my_gid;

    attr.ah_attr.grh.hop_limit = 1; // in example it is 1, why?
    attr.ah_attr.grh.sgid_index = group->local_gid_idx;
    attr.ah_attr.grh.flow_label = 0;
    attr.ah_attr.grh.traffic_class = 0;
    qp_flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    ret = ibv_modify_qp(group->qp, &attr, qp_flags);
    if(ret){
        printf("ret of rtr %d\n",ret);
        return -1;
    }
    // qp to rts
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    qp_flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    ret = ibv_modify_qp(group->qp, &attr, qp_flags);
    if(ret){
        printf("ret of rts %d\n",ret);
        return -1;
    }
    
    return 0;

}