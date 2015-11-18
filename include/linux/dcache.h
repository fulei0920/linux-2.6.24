#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>

struct nameidata;
struct vfsmount;

/*
 * linux/include/linux/dcache.h
 *
 * Dirent cache data structures
 *
 * (C) Copyright 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

#define IS_ROOT(x) ((x) == (x)->d_parent)

/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
//qstr是内核字符串的包装器。
//它存储了实际的char*字符串以及字符串长度和散列值，这使得更容易处理查找工作。
struct qstr 
{
	unsigned int hash;
	unsigned int len;
	const unsigned char *name;
};

struct dentry_stat_t {
	int nr_dentry;
	int nr_unused;
	int age_limit;          /* age in seconds */
	int want_pages;         /* pages requested by system */
	int dummy[2];
};
extern struct dentry_stat_t dentry_stat;

/* Name hashing routines. Initial hash value */
/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash()		0

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits)
 */
static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

/* Compute the hash for a name string. */
static inline unsigned int
full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}

struct dcookie_struct;

#define DNAME_INLINE_LEN_MIN 36

//在VFS中，每一个目录项都对应一个dentry对象
//例如/bin/bash，根目录/对应一个dentry对象，然后是bin目录对应一个dentry对象
//需要注意，不要认为只有目录才有dentry对象，dentry表示的是目录项，也就是目录中的条目，
//因此对于/bin/bash，bash同样对应一个dentry对象
//dentry结构的主要用途是建立文件名和相关联的inode之间的关联
//linux使用目录项缓存(简称dentry缓存)来快速访问此前的查找操作的结果
//在VFS连同文件系统实现读取的一个目录项(目录或文件)的数据之后，则创建一个dentry实例，以缓存找到的数据
//各个dentry实例组成了一个网络，与文件系统的结构形成一定的映射关系。
//但其中并非完全映射文件系统的拓扑结构，因为dentry缓存只包含文件系统结构的一小部分。
//最常用文件和目录对应的目录项才保存在内存中。原则上，可以为所有文件系统对象都生成dentry对象，
//但物理内存空间和性能原因都限制了这样做。
struct dentry
{
	//引用计数
	atomic_t d_count;
	//DCACHE_DISCONNECTED指定一个dentry当前没有连接到超级块的dentry树
	//DCACHE_UNHASHED表明该dentry实例没有包含在任何inode的散列表中
	unsigned int d_flags;		/* protected by d_lock */
	spinlock_t d_lock;		/* per dentry lock */
	//目录项对应的inode
	//如果dentry对象是为一个不存在的文件名建立的，则为NULL指针。
	//这有助于加速查找不存在的文件名，通常情况下，这与查找实际存在的文件名同样耗时
	struct inode *d_inode;		/* Where the name belongs to - NULL is negative */
	/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	//内存中所偶有活动的dentry实例都保存在一个散列表中，该散列表使用fs/dcache.c中的全局变量dentry_hashtable实现。
	//用d_hash实现的溢出链，用于解决散列碰撞
	struct hlist_node d_hash;	/* lookup hash list */
	//指向父目录的dentry对象
	//对于根目录(没有父目录)，d_parent指向其自身的dentry实例
	struct dentry *d_parent;	/* parent directory */
	//指定文件或目录的名称
	//注意，这里并不存储绝对路径，只有路径的最后一个分量，
	//例如对/usr/bin/emacs只存储emacs，因为上述链表结构已经映射了目录结构
	struct qstr d_name;
	//dentry_unused链表上的一个链表结点
	//所有使用计数器(d_count)到达0(因而任何进程都不在使用)的dentry实例都自动地放置到该链表上
	struct list_head d_lru;		/* LRU list */
	/*
	 * d_child and d_rcu can share memory
	 */
	union 
	{
		//子目录项的链表
		struct list_head d_child;	/* child of parent list */
	 	struct rcu_head d_rcu;
	} d_u;
	//与给定目录下的所有文件和子目录相关联的dentry实例，都归入到d_subdirs链表
	//子结点的d_child成员充当链表元素
	struct list_head d_subdirs;	/* our children */
	//用作链表元素，以链接表示相同文件的各个dentry对象。
	//在利用硬链接用两个不同名称表示同一个文件时，会发生这种情况。
	//对应于文件的inode的i_dentry成员用作该链表的表头
	struct list_head d_alias;	/* inode alias list */
	unsigned long d_time;		/* used by d_revalidate */
	//指向具体的文件系统的目录项操作函数指针
	//当dentry_operations为NULL时，意味着需要按照Linux默认的dentry操作方式
	//Ext2使用默认的dentry操作，所以它的dentry_operations为NULL
	struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	void *d_fsdata;			/* fs-specific data */
#ifdef CONFIG_PROFILING
	struct dcookie_struct *d_cookie; /* cookie, if any */
#endif
	//当前dentry对象表示一个装载点，那么d_mounted设置为1；否则其值为0
	int d_mounted;
	//如果文件名只是由少量字符组成，则保存在d_iname中，而不是dname中，以加速访问
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* small names */
};

/*
 * dentry->d_lock spinlock nesting subclasses:
 *
 * 0: normal
 * 1: nested
 */
enum dentry_d_lock_class
{
	DENTRY_D_LOCK_NORMAL, /* implicitly used by plain spin_lock() APIs. */
	DENTRY_D_LOCK_NESTED
};

//一些指向各种特定于文件系统可以对dentry对象执行操作的函数指针
struct dentry_operations 
{
	//使用一个dentry前判断dentry是否有效，通常网络文件系统使用
	int (*d_revalidate)(struct dentry *, struct nameidata *);
	//根据名字计算hash值，各个文件系统可以采用不同的hash算法
	int (*d_hash) (struct dentry *, struct qstr *);
	//名字比较，通常这就是一个字符串比较，但是对于不同的文件系统可能采取不同的比较算法
	//例如MS DOS可能忽略大小写 
	int (*d_compare) (struct dentry *, struct qstr *, struct qstr *);
	//引用计数为0时，删除dentry对象
	int (*d_delete)(struct dentry *);
	//减小引用计数
	void (*d_release)(struct dentry *);
	//释放目录项的inode
	void (*d_iput)(struct dentry *, struct inode *);
	//为特殊文件系统构造路径
	char *(*d_dname)(struct dentry *, char *, int);
};

/* the dentry parameter passed to d_hash and d_compare is the parent
 * directory of the entries to be compared. It is used in case these
 * functions need any directory specific information for determining
 * equivalency classes.  Using the dentry itself might not work, as it
 * might be a negative dentry which has no information associated with
 * it */

/*
locking rules:
		big lock	dcache_lock	d_lock   may block
d_revalidate:	no		no		no       yes
d_hash		no		no		no       yes
d_compare:	no		yes		yes      no
d_delete:	no		yes		no       no
d_release:	no		no		no       yes
d_iput:		no		no		no       yes
 */

/* d_flags entries */
#define DCACHE_AUTOFS_PENDING 0x0001    /* autofs: "under construction" */
#define DCACHE_NFSFS_RENAMED  0x0002    /* this dentry has been "silly
					 * renamed" and has to be
					 * deleted on the last dput()
					 */
#define	DCACHE_DISCONNECTED 0x0004
     /* This dentry is possibly not currently connected to the dcache tree,
      * in which case its parent will either be itself, or will have this
      * flag as well.  nfsd will not use a dentry with this bit set, but will
      * first endeavour to clear the bit either by discovering that it is
      * connected, or by performing lookup operations.   Any filesystem which
      * supports nfsd_operations MUST have a lookup function which, if it finds
      * a directory inode with a DCACHE_DISCONNECTED dentry, will d_move
      * that dentry into place and return that dentry rather than the passed one,
      * typically using d_splice_alias.
      */

#define DCACHE_REFERENCED	0x0008  /* Recently used, don't discard. */
#define DCACHE_UNHASHED		0x0010	

#define DCACHE_INOTIFY_PARENT_WATCHED	0x0020 /* Parent inode is watched */

extern spinlock_t dcache_lock;
extern seqlock_t rename_lock;

/**
 * d_drop - drop a dentry
 * @dentry: dentry to drop
 *
 * d_drop() unhashes the entry from the parent dentry hashes, so that it won't
 * be found through a VFS lookup any more. Note that this is different from
 * deleting the dentry - d_delete will try to mark the dentry negative if
 * possible, giving a successful _negative_ lookup, while d_drop will
 * just make the cache lookup fail.
 *
 * d_drop() is used mainly for stuff that wants to invalidate a dentry for some
 * reason (NFS timeouts or autofs deletes).
 *
 * __d_drop requires dentry->d_lock.
 */

static inline void __d_drop(struct dentry *dentry)
{
	if (!(dentry->d_flags & DCACHE_UNHASHED)) {
		dentry->d_flags |= DCACHE_UNHASHED;
		hlist_del_rcu(&dentry->d_hash);
	}
}

static inline void d_drop(struct dentry *dentry)
{
	spin_lock(&dcache_lock);
	spin_lock(&dentry->d_lock);
 	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
}

static inline int dname_external(struct dentry *dentry)
{
	return dentry->d_name.name != dentry->d_iname;
}

/*
 * These are the low-level FS interfaces to the dcache..
 */
extern void d_instantiate(struct dentry *, struct inode *);
extern struct dentry * d_instantiate_unique(struct dentry *, struct inode *);
extern struct dentry * d_materialise_unique(struct dentry *, struct inode *);
extern void d_delete(struct dentry *);

/* allocate/de-allocate */
extern struct dentry * d_alloc(struct dentry *, const struct qstr *);
extern struct dentry * d_alloc_anon(struct inode *);
extern struct dentry * d_splice_alias(struct inode *, struct dentry *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);
extern int d_invalidate(struct dentry *);

/* only used at mount-time */
extern struct dentry * d_alloc_root(struct inode *);

/* <clickety>-<click> the ramfs-type tree */
extern void d_genocide(struct dentry *);

extern struct dentry *d_find_alias(struct inode *);
extern void d_prune_aliases(struct inode *);

/* test whether we have any submounts in a subdir tree */
extern int have_submounts(struct dentry *);

/*
 * This adds the entry to the hash queues.
 */
extern void d_rehash(struct dentry *);

/**
 * d_add - add dentry to hash queues
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
 
static inline void d_add(struct dentry *entry, struct inode *inode)
{
	d_instantiate(entry, inode);
	d_rehash(entry);
}

/**
 * d_add_unique - add dentry to hash queues without aliasing
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
static inline struct dentry *d_add_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *res;

	res = d_instantiate_unique(entry, inode);
	d_rehash(res != NULL ? res : entry);
	return res;
}

/* used for rename() and baskets */
extern void d_move(struct dentry *, struct dentry *);

/* appendix may either be NULL or be used for transname suffixes */
extern struct dentry * d_lookup(struct dentry *, struct qstr *);
extern struct dentry * __d_lookup(struct dentry *, struct qstr *);
extern struct dentry * d_hash_and_lookup(struct dentry *, struct qstr *);

/* validate "insecure" dentry pointer */
extern int d_validate(struct dentry *, struct dentry *);

/*
 * helper function for dentry_operations.d_dname() members
 */
extern char *dynamic_dname(struct dentry *, char *, int, const char *, ...);

extern char * d_path(struct dentry *, struct vfsmount *, char *, int);
  
/* Allocation counts.. */

/**
 *	dget, dget_locked	-	get a reference to a dentry
 *	@dentry: dentry to get a reference to
 *
 *	Given a dentry or %NULL pointer increment the reference count
 *	if appropriate and return the dentry. A dentry will not be 
 *	destroyed when it has references. dget() should never be
 *	called for dentries with zero reference counter. For these cases
 *	(preferably none, functions in dcache.c are sufficient for normal
 *	needs and they take necessary precautions) you should hold dcache_lock
 *	and call dget_locked() instead of dget().
 */
 
static inline struct dentry *dget(struct dentry *dentry)
{
	if (dentry) 
	{
		BUG_ON(!atomic_read(&dentry->d_count));
		atomic_inc(&dentry->d_count);
	}
	return dentry;
}

extern struct dentry * dget_locked(struct dentry *);

/**
 *	d_unhashed -	is dentry hashed
 *	@dentry: entry to check
 *
 *	Returns true if the dentry passed is not currently hashed.
 */
 
static inline int d_unhashed(struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_UNHASHED);
}

static inline struct dentry *dget_parent(struct dentry *dentry)
{
	struct dentry *ret;

	spin_lock(&dentry->d_lock);
	ret = dget(dentry->d_parent);
	spin_unlock(&dentry->d_lock);
	return ret;
}

extern void dput(struct dentry *);

static inline int d_mountpoint(struct dentry *dentry)
{
	return dentry->d_mounted;
}

extern struct vfsmount *lookup_mnt(struct vfsmount *, struct dentry *);
extern struct vfsmount *__lookup_mnt(struct vfsmount *, struct dentry *, int);
extern struct dentry *lookup_create(struct nameidata *nd, int is_dir);

extern int sysctl_vfs_cache_pressure;

#endif /* __KERNEL__ */

#endif	/* __LINUX_DCACHE_H */
