#ifndef _PROCESS_MEM_
#define _PROCESS_MEM_

#include "process_mem_types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct mm_info *get_mm(int pid);
struct vma_info *get_vma(int pid, unsigned long address);
size_t read_memory(int pid, void * address, size_t size, 
                void * l_buff);
size_t write_memory(int pid, void * address, size_t size, 
                void * l_buff);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PROCESS_MEM_