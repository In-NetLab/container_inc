#include <inttypes.h>

struct iccl_ring_mr_buffer {
    char *buffer;
    uint64_t capacity;
    struct ibv_mr *mr;
    uint64_t avail_pos;
    uint64_t avail_size;
};