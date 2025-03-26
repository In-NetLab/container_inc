#include <inttypes.h>
#include "transfer.h"

#define ALLREDUCE (1 << 24)
#define ADD (1<<16)


int iccl_allreduce(struct iccl_group *group, char *src_addr, char *dst_addr, uint64_t size, int type, int opcode);
