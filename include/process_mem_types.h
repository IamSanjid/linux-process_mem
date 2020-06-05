#ifndef __P_M_TYPES
#define __P_M_TYPES

#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <linux/types.h>

/* just same as atomic64_t just to match the size with the mm_struct's pinned_vm field... */
typedef struct {
	int64_t counter;
} a64_t;

/* contains info of a vm_area_struct of a process */
struct vma_info
{
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					                within vm_mm. */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE units */
	char *path;			/* path/name of vm_area_struct->file */
};

/* contains info of mm_struct of a process */
struct mm_info
{
	uint64_t vmacache_seqnum;

	unsigned long task_size;		/* size of task vm space */
	unsigned long highest_vm_end;	/* highest vma end address */

	int map_count;		/* number of VMAs */

	unsigned long hiwater_rss; /* High-watermark of RSS usage */
	unsigned long hiwater_vm;  /* High-water virtual memory usage */

	unsigned long total_vm;	   /* Total pages mapped */
	unsigned long locked_vm;   /* Pages that have PG_mlocked set */
	a64_t    	  pinned_vm;   /* Refcount permanently increased */
	unsigned long data_vm;	   /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	unsigned long exec_vm;	   /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	unsigned long stack_vm;	   /* VM_STACK */
	unsigned long def_flags;

	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long flags; /* Must use atomic bitops to access */
};

#endif