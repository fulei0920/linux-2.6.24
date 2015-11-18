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
	//ָ���˽��̵�ǰ���Դ�����ļ�������ļ��������������Ŀ
	//����û�й��е����ޣ���Ϊ������ֵ�������ڱ�Ҫʱ����(ֻҪû�г�����Rlimitָ����ֵ���������ļ��ṹ�޹�)��
	//�����ں�ʹ�õ��ļ�������ļ�����������Ŀ������ͬ�ģ������붨�岻ͬ�������Ŀ��������ڹ���������ݽṹ�ķ���
	unsigned int max_fds;
	//һ��ָ�����飬ÿ��������ָ��һ��file�ṹ��ʵ��������һ�����ļ���������Ϣ
	//�����鵱ǰ������max_fds����
	struct file ** fd;      /* current fd array */
	//һ��ָ��λ���ָ�룬��λ�򱣴���������execϵͳ����ʱ��Ҫ�رյ��ļ�����������Ϣ
	fd_set *close_on_exec;
	//һ��ָ��λ���ָ�룬��λ������ŵ�ǰ���д��ļ�����������
	//ÿ�����ܵ��ļ�����������Ӧ��һ������λ��
	//����ñ���λ��λ�����Ӧ���ļ�����������ʹ���У����߸�������δʹ�á�
	//��ǰ����λ�õ������Ŀ��max_fdsetָ��
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
	//��ʾ��һ�δ����ļ�ʱʹ�õ��ļ�������
	int next_fd;
	//close_on_exec_init��open_fds_init��λͼ
	//��ִ��execʱ���رյ������ļ�����������close_on_exec_init�ж�Ӧ�ı���λ������λ��
	//open_fds_init��������ļ����������ϡ�
	struct embedded_fd_set close_on_exec_init;
	struct embedded_fd_set open_fds_init;
	//������̴򿪵��ļ�����ָ��
	//����0,1,2�ֱ��Ǳ�׼���롢��׼����ͱ�׼�����file�ṹ
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
