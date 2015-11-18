/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <asm/atomic.h>
#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * The embedded_fd_set is a small fd_set,
 * suitable for most tasks (which open <= BITS_PER_LONG files)
 */
struct embedded_fd_set 
{
	unsigned long fds_bits[1];
};

struct fdtable 
{
	//指定了进程当前可以处理的文件对象和文件描述符的最大数目
	//这里没有固有的上限，因为这两个值都可以在必要时增加(只要没有超出由Rlimit指定的值，但这与文件结构无关)。
	//尽管内核使用的文件对象和文件描述符的数目总是相同的，但必须定义不同的最大数目。这归因于管理相关数据结构的方法
	unsigned int max_fds;
	//一个指针数组，每个数组项指向一个file结构的实例，管理一个打开文件的所有信息
	//该数组当前长度由max_fds定义
	struct file ** fd;      /* current fd array */
	//一个指向位域的指针，该位域保存了所有在exec系统调用时将要关闭的文件描述符的信息
	fd_set *close_on_exec;
	//一个指向位域的指针，该位域管理着当前所有打开文件的描述符。
	//每个可能的文件描述符都对应着一个比特位。
	//如果该比特位置位，则对应的文件描述符处于使用中；否者该描述符未使用。
	//当前比特位置的最大数目由max_fdset指定
	fd_set *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

/*
 * Open file table structure
 */
struct files_struct 
{
  /*
   * read mostly part
   */
	atomic_t count;
	struct fdtable *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	//表示下一次打开新文件时使用的文件描述符
	int next_fd;
	//close_on_exec_init和open_fds_init是位图
	//对执行exec时将关闭的所有文件描述符，在close_on_exec_init中对应的比特位都将置位。
	//open_fds_init是最初的文件描述符集合。
	struct embedded_fd_set close_on_exec_init;
	struct embedded_fd_set open_fds_init;
	//保存进程打开的文件对象指针
	//其中0,1,2分别是标准输入、标准输出和标准错误的file结构
	struct file * fd_array[NR_OPEN_DEFAULT];
};

#define files_fdtable(files) (rcu_dereference((files)->fdt))

extern struct kmem_cache *filp_cachep;

extern void FASTCALL(__fput(struct file *));
extern void FASTCALL(fput(struct file *));

struct file_operations;
struct vfsmount;
struct dentry;
extern int init_file(struct file *, struct vfsmount *mnt,
		struct dentry *dentry, mode_t mode,
		const struct file_operations *fop);
extern struct file *alloc_file(struct vfsmount *, struct dentry *dentry,
		mode_t mode, const struct file_operations *fop);

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed))
		fput(file);
}

extern struct file * FASTCALL(fget(unsigned int fd));
extern struct file * FASTCALL(fget_light(unsigned int fd, int *fput_needed));
extern void FASTCALL(set_close_on_exec(unsigned int fd, int flag));
extern void put_filp(struct file *);
extern int get_unused_fd(void);
extern int get_unused_fd_flags(int flags);
extern void FASTCALL(put_unused_fd(unsigned int fd));
struct kmem_cache;

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable_rcu(struct rcu_head *rcu);
extern void __init files_defer_init(void);

static inline void free_fdtable(struct fdtable *fdt)
{
	call_rcu(&fdt->rcu, free_fdtable_rcu);
}

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference(fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

extern void FASTCALL(fd_install(unsigned int fd, struct file * file));

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void FASTCALL(put_files_struct(struct files_struct *fs));
void reset_files_struct(struct task_struct *, struct files_struct *);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FILE_H */
