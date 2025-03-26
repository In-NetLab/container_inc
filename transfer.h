#include "group.h"
#include <inttypes.h>
void iccl_memcpy_little_to_big(void *usr_addr, void *mr_addr, uint64_t size, uint32_t element_size);
void iccl_memcpy_big_to_little(void *usr_addr, void *mr_addr, uint64_t size, uint32_t element_size);

int iccl_post_send(struct iccl_group *group, void *addr, uint64_t size); // this addr is in the sending mr
int iccl_post_immsend(struct iccl_group *group, uint32_t imm);
int iccl_post_recv(struct iccl_group *group, void *addr, uint64_t size); // contains imm's recv
