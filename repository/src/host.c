#include "api.h"
#include "util.h"
#include <assert.h>
#include "topo_parser.h"

// 模拟上层应用数据
#define IN_DATA_COUNT 4096
int32_t in_data[IN_DATA_COUNT];
int32_t dst_data[IN_DATA_COUNT];

clock_t start_time;

void print_cost_time(const char * prefix) {
    clock_t end = clock();

    double elapsed_time = (double)(end - start_time) / CLOCKS_PER_SEC;
    printf("%s, Time taken: %f mileseconds\n", prefix, elapsed_time * 1000);
}

void init_data_to_aggregate(int rank) {     
    
    for(int i = 0; i < IN_DATA_COUNT; i++) {
        in_data[i] = i * (rank+1);
    }
}


int main(int argc, char *argv[]) {
    if(argc != 4) {
        printf("need 3 params now\n");
    }

    int world_size = atoi(argv[1]);
    char *master_addr = argv[2];
    int rank = atoi(argv[3]);

    init_data_to_aggregate(rank);

    struct inccl_group *group = inccl_group_create(world_size,rank,master_addr); // group_id=0

    struct inccl_communicator *comm = inccl_communicator_create(group, IN_DATA_COUNT * 4);
    printf("start...\n");

    start_time = clock();

    //inccl_allreduce_sendrecv(comm, in_data, IN_DATA_COUNT, dst_data);
    inccl_allreduce_write(comm, in_data, IN_DATA_COUNT, dst_data);

    print_cost_time("over");
    
    for(int i = 0; i < IN_DATA_COUNT; i++) {
        assert(dst_data[i] == 3 * i);
        // if(i < 516)
            //printf("idx: %d, in data: %d, reduce data: %d\n", i, in_data[i], dst_data[i]);
    }
    printf("result ok\n");

    return 0;
}