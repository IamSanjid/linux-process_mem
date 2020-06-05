#ifndef _PROCESS_MEM_GENL
#define _PROCESS_MEM_GENL

#include <linux/netlink.h>

#ifndef __KERNEL__
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/handlers.h>
#endif

enum {
	PROCESS_MEM_CMD_UNSPEC = 0,
	PROCESS_MEM_CMD_MM,				/* gets mm_info of a process */
	PROCESS_MEM_CMD_VMA,			/* gets vma_info of a process */
	PROCESS_MEM_CMD_GET,			/* request to get value */
	PROCESS_MEM_CMD_SET,			/* request to set value */
	__PROCESS_MEM_CMD_MAX
};

#define PROCESS_MEM_CMD_MAX (__PROCESS_MEM_CMD_MAX - 1)

enum 
{
	PROCESS_MEM_TYPE_UNSPEC = 0,
	PROCESS_MEM_TYPE_PATH,			/* path of the binary associated with the vma */
	PROCESS_MEM_TYPE_PID, 			/* Process id */
	PROCESS_MEM_TYPE_VMA, 			/* vma_info structure */
	PROCESS_MEM_TYPE_MM, 			/* mm_struct structure */
	PROCESS_MEM_TYPE_AGGR_VMA, 		/* path + vma_info structure */
	PROCESS_MEM_TYPE_NULL,
	__PROCESS_MEM_TYPE_MAX
};

#define PROCESS_MEM_TYPE_MAX (__PROCESS_MEM_TYPE_MAX - 1)

enum {
	PROCESS_MEM_CMD_ATTR_UNSPEC = 0,
	PROCESS_MEM_CMD_ATTR_PID,			/* the Process ID */
	PROCESS_MEM_CMD_ATTR_BASE_ADDR,		/* the address of the specified process */
	PROCESS_MEM_CMD_ATTR_SIZE,			/* the r/w size of the content */
	PROCESS_MEM_CMD_ATTR_BUFF_ADDR,		/* the address of the buffer content */
	PROCESS_MEM_CMD_ATTR_SIZE_ADDR,		/* the address to set the r/w bytes */
	__PROCESS_MEM_CMD_ATTR_MAX,
};

#define PROCESS_MEM_CMD_ATTR_MAX (__PROCESS_MEM_CMD_ATTR_MAX - 1)

#define PROCESS_MEM_FAMILY_NAME			"PROCESS_MEM"
#define PROCESS_MEM_FAMILY_VERSION		0x1

/*#ifdef __KERNEL__
static struct nla_policy policy[PROCESS_MEM_CMD_ATTR_MAX+1] =
{
	[PROCESS_MEM_CMD_ATTR_PID] = 
	{
		.type	= NLA_U32
	},
	[PROCESS_MEM_CMD_ATTR_BASE_ADDR] =
	{
		.type	= NLA_U64
	},
}
#else
static struct nla_policy policy[PROCESS_MEM_TYPE_MAX+1] =
{
	[PROCESS_MEM_TYPE_VMA] =
	{
		.minlen	= sizeof(struct vma_info)
	},
	[PROCESS_MEM_TYPE_MM] =
	{
		.minlen	= sizeof(struct mm_info)
	},
	[PROCESS_MEM_TYPE_AGGR_VMA] =
	{
		.type 	= NLA_NESTED
	},
}
#endif*/

#ifndef __KERNEL__
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int prep_nl_sock(struct nl_sock **m_sock);
int send_nl_msg(struct nl_sock *sock, struct nl_msg *msg);
int recv_nl_msg(struct nl_sock *sock, struct nl_msg ** ret_msg);
int request_pid_mm(struct nl_sock *sock, int f_id, int pid);
int request_pid_next_vma(struct nl_sock *sock, int f_id, int pid, 
						unsigned long address);
int request_pid_rw_mem(struct nl_sock *sock, int f_id, int pid, 
						unsigned long address, unsigned int size, 
						unsigned long ret_buff_addr, unsigned long rw_bytes,
						int vm_write);
void* get_info(struct nl_msg *msg);
void fatal(int err, const char *fmt, ...);

/*
int init(void);
int exit(void);

struct vma_info* get_vma_info(int pid, int address);
struct mm_info* get_mm_info(int pid);
*/

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __KERNEL__

#endif // _PROCESS_MEM_GENL