#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/timer.h>
#include <linux/export.h>
#include <net/genetlink.h>
#include <linux/delay.h>
#include <linux/limits.h>
#include <linux/fs.h>

#include <linux/sched.h>        // for_each_process, pr_info
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/pid.h>

#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

#include "../include/process_mem_genl.h"
#include "../include/process_mem_types.h"

#ifdef DEBUG
#define DBG(fmt, arg...) printk(KERN_DEBUG fmt, ##arg);
#else
#define DBG(fmt, arg...) do {} while(0);
#endif

static DEFINE_PER_CPU(__u32, process_mem_seqnum);
static struct genl_family family;

static struct nla_policy policy[PROCESS_MEM_CMD_ATTR_MAX+1] =
{
	[PROCESS_MEM_CMD_ATTR_PID] = 
	{
		.type	= NLA_U32
	},
	[PROCESS_MEM_CMD_ATTR_SIZE] =
	{
		.type	= NLA_U32
	},
	[PROCESS_MEM_CMD_ATTR_BASE_ADDR] =
	{
		.type	= NLA_U64
	},
	[PROCESS_MEM_CMD_ATTR_BUFF_ADDR] =
	{
		.type	= NLA_U64
	},
	[PROCESS_MEM_CMD_ATTR_SIZE_ADDR] =
	{
		.type	= NLA_U64
	},
};

static int check_root = 1;

module_param(check_root, int, 0);

static int prepare_reply(struct genl_info *info, u8 cmd, struct sk_buff **skbp, size_t size)
{
    struct sk_buff *skb;
	void *reply;

	/*
	 * If new attributes are added, please revisit this allocation
	 */
	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	if (!info) {
		int seq = this_cpu_inc_return(process_mem_seqnum) - 1;

		reply = genlmsg_put(skb, 0, seq, &family, 0, cmd);
	} else
		reply = genlmsg_put_reply(skb, info, &family, 0, cmd);
	if (reply == NULL) {
		nlmsg_free(skb);
		return -EINVAL;
	}

	*skbp = skb;
	return 0;
}

static int send_reply(struct sk_buff *skb, struct genl_info *info)
{
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(skb));
	void *reply = genlmsg_data(genlhdr);

	genlmsg_end(skb, reply);

	return genlmsg_reply(skb, info);
}

static int set_vma_reply(struct sk_buff *skb, struct vma_info *vma)
{
	struct nlattr *na;
	int aggr, rc;

	aggr = PROCESS_MEM_TYPE_AGGR_VMA;

	rc = -EINVAL;
	na = nla_nest_start_noflag(skb, aggr);
	if (!na)
		goto err;

	if (vma->path)
	{
		rc = nla_put_string(skb, PROCESS_MEM_TYPE_PATH, vma->path);
		if (rc < 0) {
			nla_nest_cancel(skb, na);
			goto err;
		}
	}
	
	rc = nla_put_64bit(skb, PROCESS_MEM_TYPE_VMA, 
						sizeof(struct vma_info), vma,
						PROCESS_MEM_TYPE_NULL);
	if (rc < 0) {
		nla_nest_cancel(skb, na);
		goto err;
	}
	nla_nest_end(skb, na);
	return 0;
err:
	return rc;
}

static size_t size_from_addr_to(void *from, void *to, size_t extra_)
{
	return ((unsigned long)to - (unsigned long)from) + extra_;
}

static int fill_vma(u32 pid, struct vma_info *vma, u64 address)
{
	struct task_struct *tsk;
	struct vm_area_struct *vm_area;
	char path[256];
	int n;
	char *p;

	tsk = pid_task(find_vpid(pid), PIDTYPE_PID);

	if (!tsk)
		return -ESRCH;
	
	if (address == 0x0)
		vm_area = tsk->mm->mmap;
	else
		vm_area = find_vma(tsk->mm, address);

	if (vm_area == NULL || address >= vm_area->vm_end)
		return -EFAULT;

	memset(vma, 0, sizeof(*vma));

	vma->vm_start = vm_area->vm_start;
	vma->vm_end = vm_area->vm_end;
	vma->vm_flags = vm_area->vm_flags;
	vma->vm_pgoff = vm_area->vm_pgoff;

	if (vm_area->vm_file)
	{
		p = d_path(&vm_area->vm_file->f_path, path, 256);
		if (p)
		{
			n = strlen(p) + 1;
			vma->path = kmalloc(sizeof(char) * n, GFP_KERNEL);
			memcpy(vma->path, p, sizeof(char) * n);
		}
	}

	return 0;
}

static int fill_mm(u32 pid, struct mm_info *mm)
{
	struct task_struct *tsk;
	tsk = pid_task(find_vpid(pid), PIDTYPE_PID);

	if (!tsk)
		return -ESRCH;

	memset(mm, 0, sizeof(*mm));
	
	mm->map_count 		= tsk->mm->map_count;
	mm->task_size		= tsk->mm->task_size;
	mm->highest_vm_end 	= tsk->mm->highest_vm_end;
	mm->flags			= tsk->mm->flags;
	mm->vmacache_seqnum	= tsk->mm->vmacache_seqnum;
	
	/* copying everything from start_code to env_end */ 
	memcpy(&mm->start_code, &tsk->mm->start_code, 
		size_from_addr_to(
			&tsk->mm->start_code, 
			&tsk->mm->env_end, 
			sizeof(tsk->mm->env_end))
	);

	/* copying everything from hiwater_rss to def_flags */ 
	memcpy(&mm->hiwater_rss, &tsk->mm->hiwater_rss, 
		size_from_addr_to(
			&tsk->mm->hiwater_rss,
			&tsk->mm->def_flags,
			sizeof(tsk->mm->def_flags)
		)
	);
	return 0;
}

static int copyout(void __user *to, const void *from, size_t n)
{
	if (access_ok(to, n)) {
		kasan_check_read(from, n);
		n = raw_copy_to_user(to, from, n);
	}
	return n;
}

static int copyin(void *to, const void __user *from, size_t n)
{
	if (access_ok(from, n)) {
		kasan_check_write(to, n);
		n = raw_copy_from_user(to, from, n);
	}
	return n;
}

static int rw_page_at(struct page* page, unsigned offset, 
					size_t bytes, unsigned long buff_addr,
					unsigned long buff_size, int write)
{
	size_t skip, copy, left, wanted;
	char __user *buf;
	void *kaddr, *to_from;

	might_fault();
	wanted = bytes;
	skip = 0;
	buf = (char*)(buff_addr + skip);
	copy = min(bytes, buff_size - skip);

	if (IS_ENABLED(CONFIG_HIGHMEM) && !fault_in_pages_writeable(buf, copy)) 
	{
		kaddr = kmap_atomic(page);
		to_from = kaddr + offset;

		/* first chunk, usually the only one */
		if (write)
			left = copyin(to_from, buf, copy);
		else
			left = copyout(buf, to_from, copy);
		copy -= left;
		skip += copy;
		to_from += copy;
		bytes -= copy;

		if (likely(!bytes)) {
			kunmap_atomic(kaddr);
			goto done;
		}
		offset = to_from - kaddr;
		buf += copy;
		kunmap_atomic(kaddr);
		copy = min(bytes, buff_size - skip);
	}
	/* Too bad - revert to non-atomic kmap */

	kaddr = kmap(page);
	to_from = kaddr + offset;
	if (write)
		left = copyin(to_from, buf, copy);
	else
		left = copyout(buf, to_from, copy);
	copy -= left;
	skip += copy;
	to_from += copy;
	bytes -= copy;
	kunmap(page);

done:
	return wanted - bytes;
}

static int vm_rw_pages(struct page **pages, unsigned offset,
			       	size_t len, unsigned long buff_addr, unsigned long size,
					int vm_write, size_t *rw_bytes)
{
	struct page *page;
	size_t copy;
	size_t copied;
	size_t total_copied;
	
	total_copied = 0;
	while (len)
	{
		page = *pages++;
		copy = PAGE_SIZE - offset;
		
		if (copy > len)
			copy = len;
		
		copied = rw_page_at(page, offset, copy, buff_addr, size, vm_write);

		if (copied < 0)
		{
			return -EFAULT;
		}
		
		total_copied += copied;
		len -= copied;
		offset = 0;
	}
	if (rw_bytes)
		*rw_bytes = total_copied;
	return 0;
}

/* Maximum number of pages kmalloc'd to hold struct page's during copy */
#define PVM_MAX_KMALLOC_PAGES (PAGE_SIZE * 2)

static int vm_rw_address_core(unsigned long addr, u32 len, unsigned long buff_addr, 
					struct page **process_pages, struct mm_struct *mm,
				    struct task_struct *task, int vm_write, size_t *rw_bytes)
{
	unsigned long pa;
	unsigned long start_offset;
	unsigned long nr_pages;
	unsigned int flags;
	unsigned long max_pages_per_loop;
	unsigned long size;
	ssize_t rc;

	int pinned_pages;
	int locked;
	size_t bytes;
	size_t total_rw_bytes;

	pa = addr & PAGE_MASK;
	start_offset = addr - pa;
	flags = 0;
	max_pages_per_loop = PVM_MAX_KMALLOC_PAGES
		/ sizeof(struct pages *);
	rc = 0;
	size = len;
	total_rw_bytes = 0;

	if (len == 0)
	{
		return 0;
	}

	nr_pages = (addr + len - 1) / PAGE_SIZE - addr / PAGE_SIZE + 1;

	if (vm_write)
		flags |= FOLL_WRITE;

	while(!rc && nr_pages)
	{
		locked = 1;
		pinned_pages = min(nr_pages, max_pages_per_loop);

		/*
		 * Get the pages we're interested in.  We must
		 * access remotely because task/mm might not
		 * current/current->mm
		 */
		down_read(&mm->mmap_sem);
		pinned_pages = get_user_pages_remote(task, mm, pa, pinned_pages,
						     flags, process_pages,
						     NULL, &locked);
		
		if (locked)
			up_read(&mm->mmap_sem);
		if (pinned_pages <= 0)
			return -EFAULT;

		bytes = pinned_pages * PAGE_SIZE - start_offset;

		if (bytes > len)
			bytes = len;
		
		rc = vm_rw_pages(process_pages, start_offset, bytes, buff_addr, size, vm_write, rw_bytes);
		if (rw_bytes)
			total_rw_bytes += *rw_bytes;

		len -= bytes;
		start_offset = 0;
		nr_pages -= pinned_pages;
		pa += pinned_pages * PAGE_SIZE;

		/* If vm_write is set, the pages need to be made dirty: */
		put_user_pages_dirty_lock(process_pages, pinned_pages,
					    vm_write);
	}
	if (rw_bytes)
		*rw_bytes = total_rw_bytes;

	return rc;
}

/* Maximum number of entries for process pages array
   which lives on stack */
#define PVM_MAX_PP_ARRAY_COUNT 16

static int vm_rw_address(u32 pid, u64 address, u32 size, u64 buff_addr, int vm_write, size_t *rw_bytes)
{
	struct task_struct *task;
	struct page *pp_stack[PVM_MAX_PP_ARRAY_COUNT];
	struct page **process_pages;
	struct mm_struct *mm;
	ssize_t rc;
	unsigned long nr_pages;

	if (size < 0)
	{
		return -EINVAL;
	}

	if (unlikely(!access_ok((void*)buff_addr, size)))
	{
		return -EFAULT;
	}

	if (size > MAX_RW_COUNT) {
		size = MAX_RW_COUNT;
	}

	process_pages = pp_stack;
	rc = 0;
	nr_pages = ((unsigned long)address + size)
				/ PAGE_SIZE - (unsigned long)address
				/ PAGE_SIZE + 1;
	
	if (nr_pages == 0)
		return 0;
	
	if (nr_pages > PVM_MAX_PP_ARRAY_COUNT) 
	{
		/* For reliability don't try to kmalloc more than
		   2 pages worth */
		process_pages = kmalloc(min_t(size_t, PVM_MAX_KMALLOC_PAGES,
					      sizeof(struct pages *)*nr_pages),
					GFP_KERNEL);

		if (!process_pages)
			return -ENOMEM;
	}

	/* Get process information */
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
		rc = -ESRCH;
		goto free_proc_pages;
	}

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm)) {
		rc = IS_ERR(mm) ? PTR_ERR(mm) : -ESRCH;
		goto free_proc_pages;
	}

	rc = vm_rw_address_core((unsigned long)address, size, (unsigned long)buff_addr, 
							process_pages, mm, task, vm_write, rw_bytes);

	mmput(mm);

free_proc_pages:
	if (process_pages != pp_stack)
		kfree(process_pages);
	return rc;
}

static int cmd_mm(struct sk_buff *skb, struct genl_info *info)
{
    struct mm_info *mm;
	struct sk_buff *rep_skb;
	size_t size;
	u32 pid;
	int rc;
    struct nlattr *na;

    if (!info->attrs[PROCESS_MEM_CMD_ATTR_PID])
    {
        return -EINVAL;
    }

    size = nla_total_size(sizeof(struct mm_info));

	rc = prepare_reply(info, PROCESS_MEM_CMD_MM, &rep_skb, size);
	if (rc < 0)
		return rc;
	
	rc = -EINVAL;
	pid = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_PID]);
	
    na = nla_reserve(rep_skb, PROCESS_MEM_TYPE_MM,
				sizeof(struct mm_info));
	if (na == NULL) {
		nlmsg_free(rep_skb);
		rc = -EMSGSIZE;
		goto err;
	}

    mm = nla_data(na);

	rc = fill_mm(pid, mm);
	if (rc < 0)
		goto err;
	
	DBG("process_mem: sending mm_info....\n");
	return send_reply(rep_skb, info);
	err:
	nlmsg_free(rep_skb);
	return rc;
}

static size_t vm_packet_size(void)
{
	size_t size;

	size = nla_total_size(NAME_MAX + 1) +
		nla_total_size_64bit(sizeof(struct vma_info)) +
		nla_total_size(0);

	return size;
}

static int cmd_vma(struct sk_buff *skb, struct genl_info *info)
{
    struct vma_info *vma;
	int rc;
	struct sk_buff *rep_skb;
	u32 pid;
	u64 address;
	size_t size;

    if (!info->attrs[PROCESS_MEM_CMD_ATTR_PID] 
        || !info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR])
    {
        return -EINVAL;
    }

    pid = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_PID]);
	address = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR]);

	size = vm_packet_size();
	
	rc = prepare_reply(info, PROCESS_MEM_CMD_VMA, &rep_skb, size);
	if (rc < 0)
		return rc;

	vma = (struct vma_info*)kmalloc(sizeof(struct vma_info), GFP_KERNEL);
	rc = fill_vma(pid, vma, address);
	if (rc < 0)
		goto err;
	
	rc = set_vma_reply(rep_skb, vma);
	if (rc < 0)
		goto err;
	
	DBG("process_mem: sending vma_info\n");
	return send_reply(rep_skb, info);
	err:
	nlmsg_free(rep_skb);
	return rc;
}

static int cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	u32 pid;
	u32 size;
	u64 address;
	u64 buff_addr;
	u64 size_addr;

	int rc;
	size_t read;

	if (!info->attrs[PROCESS_MEM_CMD_ATTR_PID] 
        || !info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_SIZE]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_BUFF_ADDR]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_SIZE_ADDR])
    {
		return -EINVAL;
    }

	pid = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_PID]);
	address = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR]);
	size = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_SIZE]);
	buff_addr = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_BUFF_ADDR]);
	size_addr = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_SIZE_ADDR]);

	DBG("process_mem: Rading %d bytes from 0x%llx", size, address);

	rc = vm_rw_address(pid, address, size, buff_addr, 0, &read);
	if (rc < 0)
		copyout((void*)(unsigned long)size_addr, &rc, sizeof(size_t));
	else
	{
		DBG("process_mem: Read %ld bytes\n", read);
		copyout((void*)(unsigned long)size_addr, &read, sizeof(size_t));
	}
	return 0;
}

static int cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	u32 pid;
	u32 size;
	u64 address;
	u64 buff_addr;
	u64 size_addr;
	
	int rc;
	size_t write;

	if (!info->attrs[PROCESS_MEM_CMD_ATTR_PID]
        || !info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_SIZE]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_BUFF_ADDR]
		|| !info->attrs[PROCESS_MEM_CMD_ATTR_SIZE_ADDR])
    {
		return -EINVAL;
    }

	pid = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_PID]);
	address = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_BASE_ADDR]);
	size = nla_get_u32(info->attrs[PROCESS_MEM_CMD_ATTR_SIZE]);
	buff_addr = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_BUFF_ADDR]);
	size_addr = nla_get_u64(info->attrs[PROCESS_MEM_CMD_ATTR_SIZE_ADDR]);

	DBG("process_mem: Writing %d bytes to 0x%llx", size, address);

	rc = vm_rw_address(pid, address, size, buff_addr, 1, &write);

	if (rc < 0)
		copyout((void*)(unsigned long)size_addr, &rc, sizeof(size_t));
	else
	{
		DBG("process_mem: Wrote %ld bytes\n", write);
		copyout((void*)(unsigned long)size_addr, &write, sizeof(size_t));
	}
	return 0;
}

static struct genl_ops ops[] = {
	{
		.cmd		= PROCESS_MEM_CMD_MM,
		.validate 	= GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit		= cmd_mm,
		.flags		= GENL_CMD_CAP_HASPOL,
	},
	{
		.cmd		= PROCESS_MEM_CMD_VMA,
		.validate 	= GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit		= cmd_vma,
		.flags		= GENL_CMD_CAP_HASPOL,
	},
	{
		.cmd 		= PROCESS_MEM_CMD_GET,
		.validate 	= GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit		= cmd_get,
		.flags		= GENL_CMD_CAP_HASPOL,
	},
	{
		.cmd		= PROCESS_MEM_CMD_SET,
		.validate 	= GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit		= cmd_set,
		.flags		= GENL_CMD_CAP_HASPOL,
	}
};

static struct genl_family family __ro_after_init = {
	.name		= PROCESS_MEM_FAMILY_NAME,
	.version	= PROCESS_MEM_FAMILY_VERSION,
	.maxattr	= PROCESS_MEM_CMD_ATTR_MAX,
    .policy		= policy,
    .module		= THIS_MODULE,
    .ops		= ops,
    .n_ops		= ARRAY_SIZE(ops),
};

static int __init process_mem_init(void)
{
    int rc;
	int i;

	printk(KERN_INFO "process_mem: initializing netlink\n");

	for (i = 0; i < ARRAY_SIZE(ops); i++)
	{
		ops[i].flags |= GENL_ADMIN_PERM & (check_root & 0xff);
	}

	rc = genl_register_family(&family);
	if (rc)
		goto failure;
    
	total_communications = 0;
    pr_info("registered process_mem.\n");
    return 0;

    failure:
	printk(KERN_DEBUG "process_mem: error occurred in %s, code: %d\n", __func__, rc);
	return -EINVAL;
}

static void process_mem_exit(void)
{
    genl_unregister_family(&family);
    printk(KERN_INFO "process_mem: exiting...\n");
}

module_init(process_mem_init);
module_exit(process_mem_exit);
MODULE_LICENSE("GPL");