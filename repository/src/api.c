#include "api.h"


/* establish temporary link between ranks and rank0 and link between rank0 and controller */
struct inccl_group *inccl_group_create(int world_size, int rank, const char *master_ip){
    struct inccl_group *group = (struct inccl_group *)malloc(sizeof(struct inccl_group));

    group->rank = rank;
    group->world_size = world_size;

    // init local ib device 
    group->local_ib_port = 1;
    group->local_gid_idx = 1;
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
    ibv_query_gid(group->local_ib_ctx, group->local_ib_port, GID_IDX, &group->local_gid);
    printf("my ip: %d\n", *(int *)(group->local_gid.raw+12));
    // group->payload_mtu = (2<<(group->local_port_attr.active_mtu + 7))-inccl_HEADER_LEN;
    // printf("group payload mtu: %d\n", group->payload_mtu);
    if(rank == 0){
        // rank0
        //group->controller_ip = getenv("CONTROLLER_IP");
        group->controller_ip = "10.215.8.149";
        printf("controller ip: %s \n", group->controller_ip);
        group->group_fd_list = (int *)calloc(world_size, sizeof(int));
        uint32_t *group_ip_list = (uint32_t *)calloc(world_size, sizeof(uint32_t));
        memcpy(group_ip_list, group->local_gid.raw+12, sizeof(uint32_t));
        // tcp connections with ranks
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(MASTER_PORT), .sin_addr.s_addr=INADDR_ANY};

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("Bind failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (listen(sockfd, world_size - 1) < 0) {
            perror("Listen failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        struct inccl_rank_exchange_info info_buf;
        for (int i = 1; i < world_size; ++i) {
            int rankfd = accept(sockfd, NULL, NULL);
            if (rankfd < 0) {
                perror("Accept failed");
                continue;
            }
            // wait to recv the info from ranks.
            recv(rankfd, &info_buf, sizeof(info_buf), MSG_WAITALL);
            group->group_fd_list[info_buf.rank] = rankfd;
            group_ip_list[info_buf.rank] = info_buf.ip;
        }

        close(sockfd);
        printf("connect to ranks success.\n");
        // tcp connection with controller
        group->controller_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (group->controller_fd < 0) {
            perror("Socket creation failed");
            return NULL;
        }
        struct sockaddr_in controller_addr;
        memset(&controller_addr, 0, sizeof(controller_addr));
        controller_addr.sin_family = AF_INET;
        controller_addr.sin_port = htons(CONTROLLER_GROUP_PORT);
        if (inet_pton(AF_INET, group->controller_ip, &controller_addr.sin_addr) <= 0) {
            perror("Invalid IP address");
            close(group->controller_fd);
            return NULL;
        }

        if (connect(group->controller_fd, (struct sockaddr*)&controller_addr, sizeof(controller_addr)) < 0) {
            perror("Connection failed");
            close(group->controller_fd);
            return NULL;
        }

        printf("connect to controller success.\n");
        // send rank info to controller and get group id
        const char *prompt = "G"; // Group
        send(group->controller_fd, prompt, 1, 0);
        send(group->controller_fd, &world_size, sizeof(int), 0);
        for (int i = 0; i < world_size; ++i) {
            send(group->controller_fd, &group_ip_list[i], sizeof(uint32_t), 0);
        }

        recv(group->controller_fd, &group->group_id, sizeof(int), MSG_WAITALL);
        printf("group id: %d!\n",group->group_id);
    }
    else{
        // other ranks
        group->master_ip = master_ip;
        // connect with master
        group->master_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (group->master_fd < 0) {
            perror("Socket creation fauint32_tiled");
            exit(EXIT_FAILURE);
        }
        struct sockaddr_in master_addr;
        memset(&master_addr, 0, sizeof(master_addr));
        master_addr.sin_family = AF_INET;
        master_addr.sin_port = htons(MASTER_PORT);
        if (inet_pton(AF_INET, master_ip, &master_addr.sin_addr) <= 0) {
            perror("Invalid IP address");
            close(group->master_fd);
            return NULL;
        }

        // 连接master
        if (connect(group->master_fd, (struct sockaddr*)&master_addr, sizeof(master_addr)) < 0) {
            perror("Connection failed");
            close(group->master_fd);
            return NULL;
        }
        printf("connect to master success.\n");
        
        // send info
        struct inccl_rank_exchange_info info_buf;
        memcpy(&info_buf.ip, group->local_gid.raw+12, sizeof(uint32_t));
        info_buf.rank = rank;
        send(group->master_fd, &info_buf, sizeof(info_buf), 0);
    }

    return group;
}



int inccl_group_destroy(struct inccl_group *group) {
    printf("destory...\n");
    return 1;
}

struct inccl_communicator *inccl_communicator_create(struct inccl_group *group, uint32_t size){
    struct inccl_communicator *comm = (struct inccl_communicator *)malloc(sizeof(struct inccl_communicator));
    comm->group = group;
    comm->pd = ibv_alloc_pd(group->local_ib_ctx);

    
    int segment_num = size / 1024 / 4;
    //printf("segment_num: %d\n",segment_num);
    comm->payload_buf_size = size * 2;
    //printf("payload_buf_size: %d\n",comm->payload_buf_size);
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
    printf("my QP number = %d\n", comm->qp->qp_num);
    if(group->rank == 0){
        // recv all qp nums and transfer to controller
        uint32_t *group_qp_num_list = (uint32_t *)calloc(group->world_size, sizeof(uint32_t));
        group_qp_num_list[0] = comm->qp->qp_num;
        for (int i = 1; i < group->world_size; ++i) {
            recv(group->group_fd_list[i], &group_qp_num_list[i], sizeof(uint32_t), MSG_WAITALL);
        }

        const char *prompt = "C"; //COMMUNICATOR
        send(group->controller_fd, prompt, 1, 0);
        for (int i = 0; i < group->world_size; ++i) {
            send(group->controller_fd, &group_qp_num_list[i], sizeof(uint32_t), 0);
            printf("rank%d qp num %d\n",i,group_qp_num_list[i]);
        }
        
        //recv controller's data and save it in "/home/ubuntu/topology.yaml"
        receive_file(group->controller_fd, "/home/ubuntu/topology.yaml");
        for (int i = 1; i < group->world_size; ++i) {
            send_file_with_length(group->group_fd_list[i], "/home/ubuntu/topology.yaml");
        }
    }
    else{
        // send qp num to master
        send(group->master_fd, &comm->qp->qp_num, sizeof(uint32_t), 0);
        // recv topology.yaml from master
        receive_file(group->master_fd, "/home/ubuntu/topology.yaml");
    }

    // get switch ip: in uint32 netorder form
    uint32_t switch_ip;
    uint32_t switch_qp_num;
    printf("parse yaml\n");
    get_switch_info("/home/ubuntu/topology.yaml", group->rank, &switch_ip, &switch_qp_num);
    // connect qp
    union ibv_gid switch_gid = group->local_gid;
    memcpy(switch_gid.raw+12,&switch_ip,4);

    //fprintf(stdout, "My QP number = 0x%x\n", comm->qp->qp_num);
    fprintf(stdout, "Remote QP number = 0x%x\n", switch_qp_num);
    fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                switch_gid.raw[0], switch_gid.raw[1], switch_gid.raw[2], switch_gid.raw[3], switch_gid.raw[4], switch_gid.raw[5], switch_gid.raw[6], switch_gid.raw[7], switch_gid.raw[8], switch_gid.raw[9], switch_gid.raw[10], switch_gid.raw[11], switch_gid.raw[12], switch_gid.raw[13], switch_gid.raw[14], switch_gid.raw[15]);
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
    printf("mtu: %d\n",attr.path_mtu);
    attr.dest_qp_num = switch_qp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.dlid = 0;

    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.is_global = 1;
    attr.ah_attr.port_num = group->local_ib_port;
    attr.ah_attr.grh.dgid = switch_gid;
    attr.ah_attr.grh.hop_limit = 64; // in example it is 1, why?
    attr.ah_attr.grh.sgid_index = group->local_gid_idx;
    attr.ah_attr.grh.flow_label = 0;
    attr.ah_attr.grh.traffic_class = 0;
    qp_flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    ret = ibv_modify_qp(comm->qp, &attr, qp_flags);
    //modify_qp_to_rtr(comm->qp,attr.dest_qp_num,0,&switch_gid);
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
    sleep(1);
    return comm;
}


int inccl_communicator_destroy(struct inccl_communicator *comm);
