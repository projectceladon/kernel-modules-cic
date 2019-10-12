#ifndef _DEPS_H
#define _DEPS_H

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/ipc_namespace.h>

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size);
#else
    void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size, struct zap_details *details);
#endif
int map_kernel_range_noflush(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages);
struct files_struct *get_files_struct(struct task_struct *task);
void put_files_struct(struct files_struct *files);
struct sighand_struct *__lock_task_sighand(struct task_struct *tsk, unsigned long *flags);
int __alloc_fd(struct files_struct *files, unsigned start, unsigned end, unsigned flags);
void __fd_install(struct files_struct *files, unsigned int fd, struct file *file);
int __close_fd(struct files_struct *files, unsigned int fd);
int can_nice(const struct task_struct *p, const int nice);
int security_binder_set_context_mgr(struct task_struct *mgr);
int security_binder_transaction(struct task_struct *from, struct task_struct *to);
int security_binder_transfer_binder(struct task_struct *from, struct task_struct *to);
int security_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file);
void mmput_async(struct mm_struct *mm);
void put_ipc_ns(struct ipc_namespace *ns);
int task_work_add(struct task_struct *task, struct callback_head *twork, bool notify);
int __close_fd_get_file_compat(unsigned int fd, struct file **res);
struct ipc_namespace *show_init_ipc_ns_compat(void);
struct ipc_namespace *get_ipc_ns_exported_compat(struct ipc_namespace *ns);
int ida_alloc_max_compat(struct ida *ida, unsigned int max, gfp_t gfp);
void ida_free_compat(struct ida *, unsigned int id);

#endif
