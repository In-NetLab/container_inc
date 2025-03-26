#include "transfer.h"
/**
 * this file is used by lib, not by user, assert the data has been copied and hton to mr.
 */
// only one wqe, send one message, cutting work is 

// from usr to mr
void iccl_memcpy_little_to_big(void *usr_addr, void *mr_addr, uint64_t size, uint32_t element_size){
    char *uaddr = (char *)usr_addr;
    char *mraddr = (char *)mr_addr;
    for(uint64_t pos = 0; pos<size; pos+=element_size){
        for(uint32_t i=0;i<element_size;++i){
            *(mraddr+pos+element_size-i) = *(uaddr+pos+i);
        }
    }
}

// from mr to usr
void iccl_memcpy_big_to_little(void *usr_addr, void *mr_addr, uint64_t size, uint32_t element_size){
    char *uaddr = (char *)usr_addr;
    char *mraddr = (char *)mr_addr;
    for(uint64_t pos = 0; pos<size; pos+=element_size){
        for(uint32_t i=0;i<element_size;++i){
            *(uaddr+pos+i) = *(mraddr+pos+element_size-i);
        }
    }
}


int iccl_post_send(struct iccl_group *group, void *addr, uint64_t size){
    struct ibv_send_wr sr;
    struct ibv_sge send_sge_list[1];
    struct ibv_send_wr *send_bad_wr;
    memset(send_sge_list, 0, sizeof(send_sge_list[0]));
    send_sge_list[0].addr = (uintptr_t)addr;
    send_sge_list[0].length = size;
    send_sge_list[0].lkey = group->send_window.mr->lkey;
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = size; // available memory extend in the ring
    sr.sg_list = send_sge_list;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_SEND ;
    // free the space of buffer
    sr.send_flags = IBV_SEND_SIGNALED;
    int ret = ibv_post_send(group->qp, &sr, &send_bad_wr);
    if(ret){
        return -1;
    }
    return 0;
}

int iccl_post_immsend(struct iccl_group *group, uint32_t imm){
    struct ibv_send_wr sr;
    struct ibv_send_wr *send_bad_wr;
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0; // distinguish from send
    sr.sg_list = NULL;
    sr.num_sge = 0;
    sr.opcode = IBV_WR_SEND_WITH_IMM;
    // free the space of buffer
    sr.send_flags = IBV_SEND_SIGNALED;
    sr.imm_data = imm;
    int ret = ibv_post_send(group->qp, &sr, &send_bad_wr);
    if(ret){
        return -1;
    }
    return 0;
}

int iccl_post_recv(struct iccl_group *group, void *addr, uint64_t size){
    struct ibv_recv_wr rr;
    struct ibv_sge receive_sge_list[1];
    struct ibv_recv_wr *receive_bad_wr;
    memset(&receive_sge_list[0], 0, sizeof(receive_sge_list[0]));
    receive_sge_list[0].addr = (uintptr_t)addr;
    receive_sge_list[0].length = size;
    receive_sge_list[0].lkey = group->recv_window.mr->lkey;

    memset(&rr, 0, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = (uint64_t)addr;
    rr.sg_list = receive_sge_list;
    rr.num_sge = 1;
    int ret = ibv_post_recv(group->qp, &rr, &receive_bad_wr);
    if(ret){
        return -1;
    }
    return 0;
}
