#include "termination_api.h"

int main(){
    struct iccl_group *group = iccl_group_create();
    iccl_group_init(group);
    int data[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int recv[16];
    iccl_allreduce(group,data,recv,sizeof(data),1,1);
}