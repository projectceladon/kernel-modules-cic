#include "deps.h"

static struct vm_struct *(*get_vm_area_ptr)(unsigned long, unsigned long) = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static void (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long) = NULL;
#else
static void (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long, struct zap_details *) = NULL;
#endif
static int (*map_kernel_range_noflush_ptr)(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages) = NULL;
static struct files_struct *(*get_files_struct_ptr)(struct task_struct *) = NULL;
static void (*put_files_struct_ptr)(struct files_struct *) = NULL;
static struct sighand_struct *(*__lock_task_sighand_ptr)(struct task_struct *, unsigned long *) = NULL;
static int (*__alloc_fd_ptr)(struct files_struct *files, unsigned start, unsigned end, unsigned flags) = NULL;
static void (*__fd_install_ptr)(struct files_struct *files, unsigned int fd, struct file *file) = NULL;
static int (*__close_fd_ptr)(struct files_struct *files, unsigned int fd) = NULL;
static int (*can_nice_ptr)(const struct task_struct *, const int) = NULL;
static int (*security_binder_set_context_mgr_ptr)(struct task_struct *mgr) = NULL;
static int (*security_binder_transaction_ptr)(struct task_struct *from, struct task_struct *to) = NULL;
static int (*security_binder_transfer_binder_ptr)(struct task_struct *from, struct task_struct *to) = NULL;
static int (*security_binder_transfer_file_ptr)(struct task_struct *from, struct task_struct *to, struct file *file) = NULL;
static void (*mmput_async_ptr)(struct mm_struct *) = NULL;
static void (*put_ipc_ns_ptr)(struct ipc_namespace *) = NULL;
static int (*task_work_add_ptr)(struct task_struct *, struct callback_head *, bool) = NULL;
static struct ipc_namespace *(*show_init_ipc_ns_ptr)(void) = NULL;

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	if (!get_vm_area_ptr)
		get_vm_area_ptr = kallsyms_lookup_name("get_vm_area");
	return get_vm_area_ptr(size, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size)
#else
void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size, struct zap_details *details)
#endif
{
	if (!zap_page_range_ptr)
		zap_page_range_ptr = kallsyms_lookup_name("zap_page_range");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	zap_page_range_ptr(vma, address, size);
#else
	zap_page_range_ptr(vma, address, size, details);
#endif
}

int map_kernel_range_noflush(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages)
{
	if (!map_kernel_range_noflush_ptr)
		map_kernel_range_noflush_ptr = kallsyms_lookup_name("map_kernel_range_noflush");
	return map_kernel_range_noflush_ptr(start, size, prot, pages);
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	if (!get_files_struct_ptr)
		get_files_struct_ptr = kallsyms_lookup_name("get_files_struct");
	return get_files_struct_ptr(task);
}

void put_files_struct(struct files_struct *files)
{
	if (!put_files_struct_ptr)
		put_files_struct_ptr = kallsyms_lookup_name("put_files_struct");
	put_files_struct_ptr(files);
}

struct sighand_struct *__lock_task_sighand(struct task_struct *tsk, unsigned long *flags)
{
	if (!__lock_task_sighand_ptr)
		__lock_task_sighand_ptr = kallsyms_lookup_name("__lock_task_sighand");
	return __lock_task_sighand_ptr(tsk, flags);
}

int __alloc_fd(struct files_struct *files, unsigned start, unsigned end, unsigned flags)
{
	if (!__alloc_fd_ptr)
		__alloc_fd_ptr = kallsyms_lookup_name("__alloc_fd");
	return __alloc_fd_ptr(files, start, end, flags);
}

void __fd_install(struct files_struct *files, unsigned int fd, struct file *file)
{
	if (!__fd_install_ptr)
		__fd_install_ptr = kallsyms_lookup_name("__fd_install");
	__fd_install_ptr(files, fd, file);
}

int __close_fd(struct files_struct *files, unsigned int fd)
{
	if (!__close_fd_ptr)
		__close_fd_ptr = kallsyms_lookup_name("__close_fd");
	return __close_fd_ptr(files, fd);
}

int can_nice(const struct task_struct *p, const int nice)
{
	if (!can_nice_ptr)
		can_nice_ptr = kallsyms_lookup_name("can_nice");
	return can_nice_ptr(p, nice);
}

int security_binder_set_context_mgr(struct task_struct *mgr)
{
	if (!security_binder_set_context_mgr_ptr)
		security_binder_set_context_mgr_ptr = kallsyms_lookup_name("security_binder_set_context_mgr");
	return security_binder_set_context_mgr_ptr(mgr);
}

int security_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transaction_ptr)
		security_binder_transaction_ptr = kallsyms_lookup_name("security_binder_transaction");
	return security_binder_transaction_ptr(from, to);
}

int security_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transfer_binder_ptr)
		security_binder_transfer_binder_ptr = kallsyms_lookup_name("security_binder_transfer_binder");
	return security_binder_transfer_binder_ptr(from, to);
}

int security_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
	if (!security_binder_transfer_file_ptr)
		security_binder_transfer_file_ptr = kallsyms_lookup_name("security_binder_transfer_file");
	return security_binder_transfer_file_ptr(from, to, file);
}

void mmput_async(struct mm_struct *mm)
{
	if (!mmput_async_ptr)
		mmput_async_ptr = kallsyms_lookup_name("mmput_async");
	mmput_async_ptr(mm);
}

void put_ipc_ns(struct ipc_namespace *ns)
{
        if (!put_ipc_ns_ptr)
                put_ipc_ns_ptr = kallsyms_lookup_name("put_ipc_ns");
        if(put_ipc_ns_ptr)
                put_ipc_ns_ptr(ns);
}

int task_work_add(struct task_struct *task, struct callback_head *twork, bool notify)
{
        if(!task_work_add_ptr)
		task_work_add_ptr = kallsyms_lookup_name("task_work_add");
        if(task_work_add_ptr)
  	        return task_work_add_ptr(task, twork, notify);
        else
                return -1;
}

struct ipc_namespace *show_init_ipc_ns_compat(void)
{
       if(!show_init_ipc_ns_ptr)
	       show_init_ipc_ns_ptr = kallsyms_lookup_name("show_init_ipc_ns");
       if(show_init_ipc_ns_ptr)
	       return show_init_ipc_ns_ptr();
       else
	       return NULL;
}

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
        __clear_bit(fd, fdt->open_fds);
        __clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
        struct fdtable *fdt = files_fdtable(files);
        __clear_open_fd(fd, fdt);
        if (fd < files->next_fd)
                files->next_fd = fd;
}

static int close_fd_get_file_backport(unsigned int fd, struct file **res)
{
        struct files_struct *files = current->files;
        struct file *file;
        struct fdtable *fdt;

        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        if (fd >= fdt->max_fds)
                goto out_unlock;
        file = fdt->fd[fd];
        if (!file)
                goto out_unlock;
        rcu_assign_pointer(fdt->fd[fd], NULL);
        __put_unused_fd(files, fd);
        spin_unlock(&files->file_lock);
        get_file(file);
        *res = file;
        return filp_close(file, files);

out_unlock:
        spin_unlock(&files->file_lock);
        *res = NULL;
        return -ENOENT;
}

int __close_fd_get_file_compat(unsigned int fd, struct file **res)
{
    int (*close_fd_get_file_ptr)(unsigned int fd, struct file **res) = NULL;

    close_fd_get_file_ptr = kallsyms_lookup_name("__close_fd_get_file");
    if(close_fd_get_file_ptr)
	return close_fd_get_file_ptr(fd, res);
    else
        return close_fd_get_file_backport(fd, res);
}

struct ipc_namespace *get_ipc_ns_exported_compat(struct ipc_namespace *ns)
{
    struct ipc_namespace *(*get_ipc_ns_exported_ptr)(struct ipc_namespace *ns) = NULL;

    get_ipc_ns_exported_ptr = kallsyms_lookup_name("get_ipc_ns_exported");
    if(get_ipc_ns_exported_ptr)
        return get_ipc_ns_exported_ptr(ns);
    else
        return get_ipc_ns(ns);
}

int ida_alloc_max_compat(struct ida *ida, unsigned int max, gfp_t gfp)
{
    int (*ida_alloc_max_ptr)(struct ida *, unsigned int, gfp_t) = NULL;

    ida_alloc_max_ptr = kallsyms_lookup_name("ida_alloc_max");
    if(ida_alloc_max_ptr)
        return ida_alloc_max_ptr(ida, max, gfp);
    else
        return ida_simple_get(ida, 0, max, gfp);

}

void ida_free_compat(struct ida *ida, unsigned int id)
{
    void (*ida_free_ptr)(struct ida *, unsigned int) = NULL;
    ida_free_ptr = kallsyms_lookup_name("ida_free");

    if(ida_free_ptr)
        return ida_free_ptr(ida, id);
    else
        return ida_simple_remove(ida, id);
}
