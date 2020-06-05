#include "include/process_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYSHARE	0x00000080

unsigned long search_int(int pid, int value)
{
    struct mm_info *mm = get_mm(pid);
    if (!mm)
        return 0;
    struct vma_info *vma = NULL;
    unsigned long last_end_addr = 0x0;
    unsigned long ret = 0;

    do
    {
        if (last_end_addr >= mm->highest_vm_end)
        {
            free(vma);
            break;
        }
        vma = get_vma(pid, last_end_addr);

        if (!vma)
            break;
    
        printf("\nStart = 0x%lx, End = 0x%lx\n", vma->vm_start, vma->vm_end);

        if (vma->vm_flags & VM_READ && vma->vm_flags & VM_WRITE && !(vma->vm_flags & VM_MAYSHARE))
        {
            size_t region_size = vma->vm_end - vma->vm_start;
            char *buff = (char*)malloc(region_size);
            
            size_t read_bytes = read_memory(pid, (void*)vma->vm_start, region_size, buff);

            if (read_bytes == region_size)
            {
                for (char *p_buff = buff; (unsigned long)p_buff < (unsigned long)buff + region_size; p_buff++)
                {
                    if (*(int*)p_buff == value)
                    {
                        ret = vma->vm_start + ((unsigned long)p_buff - (unsigned long)buff);
                        free(buff);
                        free(vma);
                        goto ret;
                    }
                }
            }
            free(buff);
        }
        last_end_addr = vma->vm_end;
        
    } while (vma);
ret:
    return ret;
}

int main(int argc, char* argv[])
{
    int pid;
    int search_value = 0x0;

    if (argc == 2)
    {
        pid = atoi(argv[1]);
    }
    else if (argc == 3)
    {
        pid = atoi(argv[1]);
        search_value = atoi(argv[2]);
    }
    else
    {
        printf("Need PID!\n");
        printf("NULL: 0x%lx\n", (unsigned long)NULL);
        return -1;
    }
    struct mm_info *mm = get_mm(pid);
    if (mm)
    {
        printf("\nCode  Segment start = 0x%lx, end = 0x%lx \n"
                    "Data  Segment start = 0x%lx, end = 0x%lx\n"
                    "Stack Segment start = 0x%lx\n"
                    "Heap Segment start = 0x%lx, end = 0x%lx\n"
                    "Highest VM End addr = 0x%lx\n",
                    mm->start_code, mm->end_code,
                    mm->start_data, mm->end_data,
                    mm->start_stack, mm->start_brk,
                    mm->brk, mm->highest_vm_end);
    
        printf("\nhiwater_rss = 0x%lx, def_flags = 0x%lx \n"
                "pinned_vm = 0x%lx, map_count = %d\n",
                    mm->hiwater_rss, mm->def_flags,
                    mm->pinned_vm.counter, mm->map_count);
    }
    unsigned long f_addr = search_int(pid, search_value);
    if (f_addr)
    {
        printf("\nFound address = 0x%lx\n", f_addr);
        int r_value = 0;
        size_t r_size = read_memory(pid, (void*)f_addr, sizeof(int), &r_value);
        if (r_value && r_size)
        {
            printf("Read %ld bytes\n", r_size);
            printf("Value:\n");
            int w_value = 0;
            scanf("%d", &w_value);
            size_t w_size = write_memory(pid, (void*)f_addr, sizeof(int), &w_value);
            printf("Wrote %ld bytes\n", w_size);
        }
    }
    return 0;
}