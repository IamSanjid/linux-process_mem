#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netlink/cli/utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/genetlink.h>

#include "include/process_mem_genl.h"
#include "include/process_mem_types.h"

#ifdef DEBUG
#define PRINTF(fmt, arg...) printf(fmt, ##arg);
#else
#define PRINTF(fmt, arg...) do {} while(0);
#endif

static struct nla_policy response_policy[PROCESS_MEM_TYPE_MAX+1] =
{
	[PROCESS_MEM_TYPE_VMA] =
	{
		.minlen	= sizeof(struct vma_info),
	},
	[PROCESS_MEM_TYPE_MM] =
	{
		.minlen	= sizeof(struct mm_info),
	},
	[PROCESS_MEM_TYPE_PATH] =
	{
		.type 	= NLA_STRING,
		.maxlen = 256,
	},
	[PROCESS_MEM_TYPE_AGGR_VMA] =
	{
		.type 	= NLA_NESTED,
	},
};

void fatal(int err, const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    fprintf(stderr, "Error: ");
    if (fmt) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
    } else
        fprintf(stderr, "%s\n", strerror_r(err, buf, sizeof(buf)));
	#ifdef EXIT_AT_FATAL
    exit(abs(err));
	#endif
}

static struct nl_sock *alloc_socket(void)
{
    struct nl_sock *sock;

    if (!(sock = nl_socket_alloc()))
		fatal(ENOBUFS, "Unable to allocate netlink socket");

    return sock;
}

static void* get_aggr_vma_info(struct nlattr *nested)
{
	struct vma_info *vma = (struct vma_info*)malloc(sizeof(struct vma_info));
	struct nlattr *attrs[PROCESS_MEM_TYPE_MAX+1];
	int err;

	err = nla_parse_nested(attrs, PROCESS_MEM_TYPE_MAX, nested, response_policy);
	if (err < 0) {
		nl_perror(err, "Error while parsing generic netlink message");
		return NULL;
	}
	memcpy(vma, nla_data(attrs[PROCESS_MEM_TYPE_VMA]), sizeof(struct vma_info));
	if (attrs[PROCESS_MEM_TYPE_PATH])
	{
		char *path = nla_get_string(attrs[PROCESS_MEM_TYPE_PATH]);
		vma->path = (char*)malloc(strlen(path));
		strncpy(vma->path, path, strlen(path));
	}
	return vma;
}

void* get_info(struct nl_msg *msg)
{
    struct genlmsghdr* gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr* attr = genlmsg_attrdata(gnlh, 0);
    int remaining = genlmsg_attrlen(gnlh, 0);

    nla_for_each_attr(attr, attr, remaining, remaining) {
        switch (attr->nla_type) {
			case PROCESS_MEM_TYPE_AGGR_VMA:
				return get_aggr_vma_info(attr);
				break;
			case PROCESS_MEM_TYPE_MM:
                /* the data which we're interested in... */
				return nla_data(attr);
				break;
            default:
				return NULL;
                break;
        }
    }
    return NULL;
}

int send_nl_msg(struct nl_sock *sock, struct nl_msg *msg)
{
	int err = 0;
	
	if ((err = nl_send_auto(sock, msg)) < 0)
	{
		fatal(err, "Unable to send message: %s", nl_geterror(err));
		return err;
	}
	return 0;
}

// copied and edited a little bit from recvmsgs...
int recv_nl_msg(struct nl_sock *sock, struct nl_msg ** ret_msg)
{
	int n, err = 0, multipart = 0, interrupted = 0, nrecv = 0;
	unsigned char *buf = NULL;
	struct nlmsghdr *hdr;

	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	struct ucred *creds = NULL;

continue_reading:
    /* Receive actual bytes */
	n = nl_recv(sock, &nla, &buf, &creds);

	if (n <= 0)
		return n;
	
	PRINTF("recv_nl_msg(%p): Read %d bytes\n", sock, n);

    /* convert the received buffer to nlmsghdr type */
	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok(hdr, n)) 
	{
        /* free previous nl_msg */
		nlmsg_free(msg);
        /* get the received nl_msg */
		msg = nlmsg_convert(hdr);
		if (!msg)
		{
			err = -NLE_NOMEM;
			goto out;
		}

        /* set the peer of the socket... */
		nlmsg_set_src(msg, &nla);
		/* set the ucred if contains... */
        if (creds)
			nlmsg_set_creds(msg, creds);
		
		nrecv++;

        /* checking for if it got multipart */
		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = 1;
		
        /* if the module was interrupted... */
		if (hdr->nlmsg_flags & NLM_F_DUMP_INTR)
		{
			interrupted = 1;
		}

        /* if the multipart msg is finished */
		if (hdr->nlmsg_type == NLMSG_DONE)
		{
			multipart = 0;
			goto skip;
		}
        /* some error chicking */
		else if (hdr->nlmsg_type == NLMSG_NOOP)
		{
			goto skip;
		}
		else if (hdr->nlmsg_type == NLMSG_OVERRUN)
		{
			err = -NLE_MSG_OVERFLOW;
			goto out;
		}
		else if (hdr->nlmsg_type == NLMSG_ERROR)
		{
			struct nlmsgerr *e = nlmsg_data(hdr);
			if (hdr->nlmsg_len < (unsigned int)nlmsg_size(sizeof(*e))) 
			{
				err = -NLE_MSG_TRUNC;
				goto out;
			}
			else if (e->error) 
			{
				err = -nl_syserr2nlerr(e->error);
				goto out;
			}
		}
		else
		{
            /* a valid message is received... */
			PRINTF("Type: NLMSG_VALID \n");
			goto skip;
		}
		skip:
		err = 0;
		/* get the next header */
        hdr = nlmsg_next(hdr, &n);
	}

    /* assign the current header to the return pointer. */
	*ret_msg = msg;

    free(buf);
	free(creds);
	buf = NULL;
	creds = NULL;
	if (multipart)
	{
		goto continue_reading;
	}
	//stop:
	err = 0;

	out:
	free(buf);
	free(creds);
	if (interrupted)
		err = -NLE_DUMP_INTR;
	if (!err)
		err = nrecv;

	return err;
}

int request_pid_mm(struct nl_sock *sock, int f_id, int pid)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
    
    /*
     * Steps:
     * 1. Allocate a nl_msg
     * 2. Assign the nl_msg to genl_hdr
     * 3. Set your attributes
     * 4. Send the nl_msg
     */

	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		fatal(NLE_NOMEM, "Unable to allocate netlink message");
		return NLE_NOMEM;
	}

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, f_id,
			  0, 0, PROCESS_MEM_CMD_MM, PROCESS_MEM_FAMILY_VERSION);
	
	if (hdr == NULL)
	{
		fatal(ENOMEM, "Unable to write genl header");
		return ENOMEM;
	}
    if ((err = nla_put_u32(msg, PROCESS_MEM_CMD_ATTR_PID, pid)) < 0)
	{	
		fatal(err, "Unable to add attribute: %s", nl_geterror(err));
		return err;
	}
    
	err = send_nl_msg(sock, msg);
	nlmsg_free(msg);
	return err;
}

int request_pid_next_vma(struct nl_sock *sock, int f_id, int pid, 
						unsigned long address)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
    /*
     * Steps:
     * 1. Allocate a nl_msg
     * 2. Assign the nl_msg to genl_hdr
     * 3. Set your attributes
     * 4. Send the nl_msg
     */

	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		fatal(NLE_NOMEM, "Unable to allocate netlink message");
		return NLE_NOMEM;
	}

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, f_id,
			  0, 0, PROCESS_MEM_CMD_VMA, PROCESS_MEM_FAMILY_VERSION);
	
	if (hdr == NULL)
	{
		fatal(ENOMEM, "Unable to write genl header");
		return ENOMEM;
	}

	if ((err = nla_put_u32(msg, PROCESS_MEM_CMD_ATTR_PID, pid)) < 0)
	{
		fatal(err, "Unable to add attribute: %s", nl_geterror(err));
		return err;
	}

	if ((err = nla_put_u64(msg, PROCESS_MEM_CMD_ATTR_BASE_ADDR, address)) < 0)
	{
		fatal(err, "Unable to add attribute: %s", nl_geterror(err));
		return err;
	}

	err = send_nl_msg(sock, msg);
	nlmsg_free(msg);
	return err;
}

int request_pid_rw_mem(struct nl_sock *sock, int f_id, int pid, 
						unsigned long address, unsigned int size, 
						unsigned long ret_buff_addr, unsigned long rw_bytes,
						int vm_write)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	int type;
    
	type = vm_write ? PROCESS_MEM_CMD_SET : PROCESS_MEM_CMD_GET;
	/*
     * Steps:
     * 1. Allocate a nl_msg
     * 2. Assign the nl_msg to genl_hdr
     * 3. Set your attributes
     * 4. Send the nl_msg
     */

	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		fatal(NLE_NOMEM, "Unable to allocate netlink message");
		return NLE_NOMEM;
	}

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, f_id,
			  0, 0, type, PROCESS_MEM_FAMILY_VERSION);
	
	if (hdr == NULL)
	{
		fatal(ENOMEM, "Unable to write genl header");
		return ENOMEM;
	}

	if ((err = nla_put_u32(msg, PROCESS_MEM_CMD_ATTR_PID, pid)) < 0)
	{
		goto attr_err;
	}

	if ((err = nla_put_u64(msg, PROCESS_MEM_CMD_ATTR_BASE_ADDR, address)) < 0)
	{
		goto attr_err;
	}

	if ((err = nla_put_u32(msg, PROCESS_MEM_CMD_ATTR_SIZE, size)) < 0)
	{
		goto attr_err;
	}

	if ((err = nla_put_u64(msg, PROCESS_MEM_CMD_ATTR_BUFF_ADDR, ret_buff_addr)) < 0)
	{
		goto attr_err;
	}

	if ((err = nla_put_u64(msg, PROCESS_MEM_CMD_ATTR_SIZE_ADDR, rw_bytes)) < 0)
	{
		goto attr_err;
	}

	err = send_nl_msg(sock, msg);
	nlmsg_free(msg);
	return err;
attr_err:
	fatal(err, "Unable to add attribute: %s", nl_geterror(err));
	return err;
}

int prep_nl_sock(struct nl_sock **m_sock)
{
	struct nl_sock *sock;
	int err;

    /*
     * Steps:
     * 1. Allocate socket
     * 2. Connect to the netlink controller
     * 3. Resolve the family id 
     */


	sock = alloc_socket();

	if (!sock)
		return -ENOMEM;

	/* disable seq checks on multicast sockets */
	nl_socket_disable_seq_check(sock);
	nl_socket_disable_auto_ack(sock);

	err = genl_connect(sock);
	if (err < 0) {
        nl_perror(err, "Unable to open netlink socket");
        return err;
    }

	if ((err = genl_ctrl_resolve(sock, PROCESS_MEM_FAMILY_NAME)) < 0)
	{
		nl_close(sock);
		nl_socket_free(sock);
		fatal(err, "Resolving of \"%s\" failed", PROCESS_MEM_FAMILY_NAME);
		return err;
	}

	*m_sock = sock;

	return err;
}