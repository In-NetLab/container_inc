#include "termination_api.h"


inline static uint64_t min6(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    uint64_t t1 = a < b ? a : b;
    uint64_t t2 = t1 < c ? t1 : c;
    uint64_t t3 = t2 < d ? t2 : d;
    uint64_t t4 = t3 < e ? t3 : e;
    return t4 < f ? t4 : f;
}

// remember to change to multi threads  
int iccl_allreduce(struct iccl_group *group, char *src_addr, char *dst_addr, uint64_t size, int type __attribute__((unused)), int opcode __attribute__((unused))){
    // send the control message
    uint32_t imm __attribute__((unused)) = ALLREDUCE || ADD || group->group_id;
    // cut into messages, and send messages within the send_window size, need to post recv first.
    // then wait for the cqe(send or recv, not decided, but )
    uint64_t sent_size = 0;
    uint64_t received_size = 0; // cqe of receive
    uint64_t tosend;
    int message_num = 0;
    int recv_cqe = 0, send_cqe = 0;
    struct ibv_wc *wc = (struct ibv_wc *)malloc(sizeof(struct ibv_wc));
    while(sent_size < size){
        while(group->send_window.avail_size && group->recv_window.avail_size && sent_size < size){
            tosend = min6(
                size-sent_size,
                group->send_window.capacity - group->send_window.avail_pos, 
                group->send_window.avail_size,
                group->recv_window.capacity - group->recv_window.avail_pos, 
                group->recv_window.avail_size,
                group->message_size            
            );

            iccl_memcpy_little_to_big(src_addr+sent_size, group->send_window.buffer+group->send_window.avail_pos,tosend,sizeof(int));
            int ret; 
            //ret = iccl_post_recv(group, group->recv_window.buffer+group->recv_window.avail_pos, tosend);
            printf("post recv %d\n", ret); // assert 0
            ret = iccl_post_send(group,group->send_window.buffer+group->send_window.avail_pos,tosend);
            printf("post send %d\n", ret); // assert 0
            group->recv_window.avail_pos += tosend;
            group->recv_window.avail_pos %= group->recv_window.capacity;
            group->recv_window.avail_size -= tosend;
            
            sent_size+=tosend;
            group->send_window.avail_pos += tosend;
            group->send_window.avail_pos %= group->send_window.capacity;
            group->send_window.avail_size -= tosend;
            message_num+=1;
        }

        // wait for cqe
        do
        {
            int result = ibv_poll_cq(group->cq, 1, wc);
            //accum+=result;
            if(result>0){
                printf("result %d\n", result); // assert 1
                struct ibv_wc *tmp = wc;
                printf("tmp->status %d\n", tmp->status);
                printf("tmp->opcode %d\n", tmp->opcode);

                if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV){
                    recv_cqe+=1;
                    char *recv_addr = (char *)tmp->wr_id;
                    uint32_t cqe_size = tmp->byte_len;
                    iccl_memcpy_big_to_little(dst_addr+received_size,recv_addr,cqe_size,sizeof(int));
                    received_size+=cqe_size;
                    group->recv_window.avail_size += cqe_size;
                }else if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_SEND){
                    send_cqe+=1;
                    uint64_t extend_size = tmp->wr_id;
                    group->send_window.avail_size+=extend_size;
                    break;
                }
            }
        }
        while(send_cqe != message_num || recv_cqe != message_num);

    }

    // wait for cqe
    while(send_cqe != message_num || recv_cqe != message_num){
        int result = ibv_poll_cq(group->cq, 1, wc);
        //accum+=result;
        if(result>0){
            printf("result %d\n", result);
            struct ibv_wc *tmp = wc;
            printf("tmp->status %d\n", tmp->status);
            printf("tmp->opcode %d\n", tmp->opcode);

            if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_RECV){
                recv_cqe+=1;
                char *recv_addr = (char *)tmp->wr_id;
                uint32_t cqe_size = tmp->byte_len;
                iccl_memcpy_big_to_little(dst_addr+received_size,recv_addr,cqe_size,sizeof(int));
                received_size+=cqe_size;
                group->recv_window.avail_size += cqe_size;
            }else if(tmp->status==IBV_WC_SUCCESS && tmp->opcode==IBV_WC_SEND){
                send_cqe+=1;
                uint64_t extend_size = tmp->wr_id;
                group->send_window.avail_size+=extend_size;
                break;
            }
        }
    }

    return 0;

    
}



