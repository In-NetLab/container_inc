#include "../comm_lib/api.h"

int main(){
    gender = 0;
    //ip_p = "127.0.0.1";
    ip_p = "10.0.1.1";
    struct iccl_group *group = iccl_group_create(0);
    int send_data[8] = {0,1,2,3,4,5,6,7};
    int receive_data[8];
    struct iccl_communicator *comm = iccl_communicator_create(group, sizeof(send_data));
    iccl_allreduce(comm, send_data, receive_data, sizeof(send_data), 0,0);
    for(int i=0;i<8;++i){
        printf("%d ",receive_data[i]);
    }
    printf("\n");
}