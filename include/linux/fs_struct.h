#ifndef _LINUX_FS_STRUCT_H
#define _LINUX_FS_STRUCT_H

struct dentry;
struct vfsmount;


//fs_struct保存了进程的文件系统相关数据
struct fs_struct 
{
	//结构的使用计数
	atomic_t count;	
	//保护该结构体的锁
	rwlock_t lock;	
	//默认的文件访问权限, 它表示将要在打开的文件上设置的许可权
	//标准的掩码，用于设置新文件的权限
	//其值可以使用umask命令读取或设置。在内部由同名的系统调用完成
	int umask;		
	//进程根目录的目录项对象
	struct dentry * root;	
	//进程当前工作目录的目录项对象
	struct dentry * pwd;	
	//可供选择的根目录的目录项对象
	struct dentry * altroot;	
	//根目录的安装点对象
	struct vfsmount * rootmnt;	
	//pwd的安装点对象
	struct vfsmount * pwdmnt;	
	//可供选择的根目录的安装点对象
	struct vfsmount *  altrootmnt;	
};

#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

extern struct kmem_cache *fs_cachep;

extern void exit_fs(struct task_struct *);
extern void set_fs_altroot(void);
extern void set_fs_root(struct fs_struct *, struct vfsmount *, struct dentry *);
extern void set_fs_pwd(struct fs_struct *, struct vfsmount *, struct dentry *);
extern struct fs_struct *copy_fs_struct(struct fs_struct *);
extern void put_fs_struct(struct fs_struct *);

#endif /* _LINUX_FS_STRUCT_H */
