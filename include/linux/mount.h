/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

//禁止setuid执行
#define MNT_NOSUID	0x01
//装载时设备文件不存在
//如果装载的文件系统是虚拟的，即没有物理后端设备，则该标志置位
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20

//专用于NFS和AFS的，用来标记子装载，设置了该标记的装载允许自动移除
#define MNT_SHRINKABLE	0x100
//如果vfsmount是共享装载，则该标志置位
#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
//如果vfsmount是不可绑定装载，则该标志置位
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
//传播标志掩码
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */

//在Linux文件系统中，只有一颗目录树，一个新的块设备必须mount到现有的目录下，
//我们把它称为安装点。每一个安装点都对应一个vfsmount对象

//表示一个已经装载的文件系统
struct vfsmount 
{
	struct list_head mnt_hash;
	//指向父文件系统的vfsmount对象
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	//安装点的dentry对象
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	//本设备根目录的dentry对象
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* pointer to superblock */
	//子文件系统链表的表头
	struct list_head mnt_mounts;	/* list of children, anchored here */
	//子文件系统链表的元素
	struct list_head mnt_child;	/* and going through their mnt_child */
	int mnt_flags;
	/* 4 bytes hole on 64bits arches */
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */
	//装载的文件系统所属的命名空间
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	//引用计数
	atomic_t mnt_count;
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern void free_vfsmnt(struct vfsmount *mnt);
extern struct vfsmount *alloc_vfsmnt(const char *name);
extern struct vfsmount *do_kern_mount(const char *fstype, int flags, const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

struct nameidata;

extern int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);
extern void shrink_submounts(struct vfsmount *mountpoint, struct list_head *mounts);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif
#endif /* _LINUX_MOUNT_H */
