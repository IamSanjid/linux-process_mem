#include "include/process_mem.h"
#include "include/process_mem_genl.h"

struct nl_sock *sock;
int f_id;

#ifdef DEBUG
#define PRINTF(fmt, arg...) printf(fmt, ##arg);
#else
#define PRINTF(fmt, arg...) do {} while(0);
#endif

struct mm_info *get_mm(int pid)
{
    struct nl_msg *msg = NULL;
    struct mm_info *mm = NULL;
    int err;
    /* request for mm */
    err = request_pid_mm(sock, f_id, pid);
    if (err < 0)
	{
        fatal(err, "Unable to send message: %s", nl_geterror(err));
		mm = NULL;
        goto out;
	}
    /* receive message */
    err = recv_nl_msg(sock, &msg);
	if (err < 0)
	{
		fatal(err, "Unable to receive message: %s", nl_geterror(err));
		mm = NULL;
        goto out;
	}
    mm = get_info(msg);
out:
    nlmsg_free(msg);
    return mm;
}

struct vma_info *get_vma(int pid, unsigned long address)
{
    struct nl_msg *msg = NULL;
    struct vma_info *vm = NULL;
    int err;
    /* request for vma */
    err = request_pid_next_vma(sock, f_id, pid, address);
    if (err < 0)
	{
        fatal(err, "Unable to send message: %s", nl_geterror(err));
		vm = NULL;
        goto out;
	}
    /* receive message */
    err = recv_nl_msg(sock, &msg);
	if (err < 0)
	{
		fatal(err, "Unable to receive message: %s", nl_geterror(err));
		vm = NULL;
        goto out;
	}
    vm = get_info(msg);
out:
    nlmsg_free(msg);
    return vm;
}

size_t read_memory(int pid, void * address, size_t size, 
                void * l_buff)
{
    size_t read_bytes = 0;
    int err;
    /* request to get bytes */
    err = request_pid_rw_mem(sock, f_id, pid, (unsigned long)address, 
                        size, (unsigned long)l_buff, (unsigned long)&read_bytes, 0);
    if (err < 0)
	{
		return err;
	}
    return read_bytes;
}

size_t write_memory(int pid, void * address, size_t size, 
                void * l_buff)
{
    size_t write_bytes = 0;
    int err;
    /* request to set bytes */
    err = request_pid_rw_mem(sock, f_id, pid, (unsigned long)address, 
                        size, (unsigned long)l_buff, (unsigned long)&write_bytes, 1);
    if (err < 0)
	{
		return err;
	}
    return write_bytes;
}

void __attribute__ ((constructor)) initLibrary(void) 
{
    f_id = prep_nl_sock(&sock);
	if (f_id < 0)
	{
        exit(-1);
	}
    PRINTF("process_mem_lib initialized!\n");
}

void __attribute__ ((destructor)) cleanUpLibrary(void) 
{
    nl_close(sock);
	nl_socket_free(sock);
    PRINTF("process_mem_lib exited\n");
}