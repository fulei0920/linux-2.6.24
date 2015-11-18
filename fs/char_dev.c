/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/seq_file.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include "internal.h"

/*
 * capabilities for /dev/mem, /dev/kmem and similar directly mappable character
 * devices
 * - permits shared-mmap for read, write and/or exec
 * - does not permit private mmap in NOMMU mode (can't do COW)
 * - no readahead or I/O queue unplugging required
 */
struct backing_dev_info directly_mappable_cdev_bdi = {
	.capabilities	= (
#ifdef CONFIG_MMU
		/* permit private copies of the data to be taken */
		BDI_CAP_MAP_COPY |
#endif
		/* permit direct mmap, for read, write or exec */
		BDI_CAP_MAP_DIRECT |
		BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP),
};

//用于字符设备的数据库
//散列表，使用主设备号作为散列键
//散列方法相当简单:major % 255
static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

//只用于字符设备的设备号数据库
//用于管理为驱动程序分配的设备号范围
//驱动程序可以请求一个动态的设备号，或者指定一个范围，从中获取
//使用散列表来跟踪已分配的设备号范围，使用主设备号作为散列键
//注意，内核并不是为每一个字符设备编号定义一个 char_device_struct 结构，而是为一组对应同一个字符设备驱动的设备编号范围定义一个或多个(当编号范围过大时)char_device_struct 结构。
static struct char_device_struct {
	struct char_device_struct *next;//链接同一散列行中的所有散列元素
	unsigned int major;//指定了主设备号
	unsigned int baseminor;//包含minorct个从设备号的连续范围中最小的从设备号
	int minorct;
	char name[64];//为该设备提供了一个标识符
	struct file_operations *fops;//指向与该设备关联的file_operations实例
	struct cdev *cdev;		/* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

/* index in the above */
//根据主设备号计算散列位置
static inline int major_to_index(int major)
{
	return major % CHRDEV_MAJOR_HASH_SIZE;
}

#ifdef CONFIG_PROC_FS

void chrdev_show(struct seq_file *f, off_t offset)
{
	struct char_device_struct *cd;

	if (offset < CHRDEV_MAJOR_HASH_SIZE) {
		mutex_lock(&chrdevs_lock);
		for (cd = chrdevs[offset]; cd; cd = cd->next)
			seq_printf(f, "%3d %s\n", cd->major, cd->name);
		mutex_unlock(&chrdevs_lock);
	}
}

#endif /* CONFIG_PROC_FS */

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this functions will dynamically allocate a major and return
 * its number.
 *
 * If major > 0 this function will attempt to reserve the passed range of
 * minors and will return zero on success.
 *
 * Returns a -ve errno on failure.
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
			   int minorct, const char *name)
{
	struct char_device_struct *cd, **cp;
	int ret = 0;
	int i;

	cd = kzalloc(sizeof(struct char_device_struct), GFP_KERNEL);
	if (cd == NULL)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&chrdevs_lock);

	/* temporary */
	//如果申请的设备编号范围的主设备号为 0，那么表示设备驱动程序请求动态分配一个主设备号。
	//动态分配主设备号的原则是从散列表的最后一个桶向前寻找，那个桶是空的，主设备号就是相应散列桶的序号。
	//所以动态分配的主设备号总是小于 256，如果每个桶都有字符设备编号了，那动态分配就会失败。
	if (major == 0)
	{
		for (i = ARRAY_SIZE(chrdevs)-1; i > 0; i--) 
		{
			if (chrdevs[i] == NULL)
				break;
		}

		if (i == 0)
		{
			ret = -EBUSY;
			goto out;
		}
		major = i;
		ret = major;
	}

	cd->major = major;
	cd->baseminor = baseminor;
	cd->minorct = minorct;
	strncpy(cd->name, name, 64);

	i = major_to_index(major);

	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		//同一个散列桶中的字符设备编号范围是主设备号递增排序的。
		//同一个散列桶中的字符设备编号范围是按起始次设备号递增排序的。
		if ((*cp)->major > major ||	
		    ((*cp)->major == major && (((*cp)->baseminor >= baseminor) ||((*cp)->baseminor + (*cp)->minorct > baseminor))))
			break;

	/* Check for overlapping minor ranges.  */
	if (*cp && (*cp)->major == major) 
	{
		int old_min = (*cp)->baseminor;
		int old_max = (*cp)->baseminor + (*cp)->minorct - 1;
		int new_min = baseminor;
		int new_max = baseminor + minorct - 1;

		/* New driver overlaps from the left.  */
		if (new_max >= old_min && new_max <= old_max) 
		{
			ret = -EBUSY;
			goto out;
		}

		/* New driver overlaps from the right.  */
		if (new_min <= old_max && new_min >= old_min) {
			ret = -EBUSY;
			goto out;
		}
	}

	cd->next = *cp;
	*cp = cd;
	mutex_unlock(&chrdevs_lock);
	return cd;
out:
	mutex_unlock(&chrdevs_lock);
	kfree(cd);
	return ERR_PTR(ret);
}

static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor, int minorct)
{
	struct char_device_struct *cd = NULL, **cp;
	int i = major_to_index(major);

	mutex_lock(&chrdevs_lock);
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major == major &&
		    (*cp)->baseminor == baseminor &&
		    (*cp)->minorct == minorct)
			break;
	if (*cp)
	{
		cd = *cp;
		*cp = cd->next;
	}
	mutex_unlock(&chrdevs_lock);
	return cd;
}

/**
 * register_chrdev_region() - register a range of device numbers
 * @from: the first in the desired range of device numbers; must include
 *        the major number.
 * @count: the number of consecutive device numbers required
 * @name: the name of the device or driver.
 *
 * Return value is zero on success, a negative error code on failure.
 */

//分配一个或多个连续的设备编号
//from -- 请求分配的设备编号范围的起始值。from的次设备号经常被置为0，但对该函数来讲并不是必需的。
//count -- 是所请求的连续设备编号的个数。注意，如果count非常大，则所请求的范围可能和下一个主设备号重叠，
//		但只要我们所请求的编号范围是可用的，则不会带来任何问题。
//name -- 和该编号范围关联的设备名称，它将出现在/proc/devices和sysfs中
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next)
	{
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n), next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
	to = n;
	for (n = from; n < to; n = next) 
	{
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}

/**
 * alloc_chrdev_region() - register a range of char device numbers
 * @dev: output parameter for first assigned number
 * @baseminor: first of the requested range of minor numbers
 * @count: the number of minor numbers required
 * @name: the name of the associated device or driver
 *
 * Allocates a range of char device numbers.  The major number will be
 * chosen dynamically, and returned (along with the first minor number)
 * in @dev.  Returns zero or a negative error code.
 */
//动态分配设备编号。这个函数好像并没有检查范围过大的情况(跨越多个主设备号)，不过动态分配总是找个空的散列桶，所以问题也不大。
//动态分配的缺点是:由于分配的主设备号不能保证始终一致，所以无法预先创建设备节点。
//对于驱动程序的一般用法，这倒不是什么问题，因为一旦分配了设备号，就可以从/proc/devices中读取得到。
//dev -- 仅用于输出的参数，在成功完成调用后将保存已分配范围的第一个编号。
//baseminor -- 要使用的被请求的第一个次设备号，它通常是0。
//count -- 是所请求的连续设备编号的个数。注意，如果count非常大，则所请求的范围可能和下一个主设备号重叠，
//		但只要我们所请求的编号范围是可用的，则不会带来任何问题。
//name -- 和该编号范围关联的设备名称，它将出现在/proc/devices和sysfs中
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}

/**
 * register_chrdev() - Register a major number for character devices.
 * @major: major device number or 0 for dynamic allocation
 * @name: name of this range of devices
 * @fops: file operations associated with this devices
 *
 * If @major == 0 this functions will dynamically allocate a major and return
 * its number.
 *
 * If @major > 0 this function will attempt to reserve a device with the given
 * major number and will return zero on success.
 *
 * Returns a -ve errno on failure.
 *
 * The name of this device has nothing to do with the name of the device in
 * /dev. It only helps to keep track of the different owners of devices. If
 * your module name has only one type of devices it's ok to use e.g. the name
 * of the module here.
 *
 * This function registers a range of 256 minor numbers. The first minor number
 * is 0.
 */
//一个老式分配设备编号范围的函数。
//它分配一个单独主设备号和 0 ~ 255 的次设备号范围。
//如果申请的主设备号为 0 则动态分配一个。
//该函数还需传入一个 file_operations 结构的指针，函数内部自动分配了一个新的cdev结构。
int register_chrdev(unsigned int major, const char *name,
		    const struct file_operations *fops)
{
	struct char_device_struct *cd;
	struct cdev *cdev;
	char *s;
	int err = -ENOMEM;

	cd = __register_chrdev_region(major, 0, 256, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	
	cdev = cdev_alloc();
	if (!cdev)
		goto out2;

	cdev->owner = fops->owner;
	cdev->ops = fops;
	kobject_set_name(&cdev->kobj, "%s", name);
	for (s = strchr(kobject_name(&cdev->kobj),'/'); s; s = strchr(s, '/'))
		*s = '!';
		
	err = cdev_add(cdev, MKDEV(cd->major, 0), 256);
	if (err)
		goto out;

	cd->cdev = cdev;

	return major ? 0 : cd->major;
out:
	kobject_put(&cdev->kobj);
out2:
	kfree(__unregister_chrdev_region(cd->major, 0, 256));
	return err;
}

/**
 * unregister_chrdev_region() - return a range of device numbers
 * @from: the first in the range of numbers to unregister
 * @count: the number of device numbers to unregister
 *
 * This function will unregister a range of @count device numbers,
 * starting with @from.  The caller should normally be the one who
 * allocated those numbers in the first place...
 */
//释放设备编号
void unregister_chrdev_region(dev_t from, unsigned count)
{
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
}

void unregister_chrdev(unsigned int major, const char *name)
{
	struct char_device_struct *cd;
	cd = __unregister_chrdev_region(major, 0, 256);
	if (cd && cd->cdev)
		cdev_del(cd->cdev);
	kfree(cd);
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
	struct module *owner = p->owner;
	struct kobject *kobj;

	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&p->kobj);
	if (!kobj)
		module_put(owner);
	return kobj;
}

void cdev_put(struct cdev *p)
{
	if (p) 
	{
		struct module *owner = p->owner;
		kobject_put(&p->kobj);
		module_put(owner);
	}
}

/*
 * Called every time a character special file is opened
 */
//用于打开字符设备的通用函数
int chrdev_open(struct inode * inode, struct file * filp)
{
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	spin_lock(&cdev_lock);
	p = inode->i_cdev;
	//假定表示设备文件的inode此前没有打开过。根据车次的设备号，
	//kobject_lookup查询字符设备的数据库，并返回与该驱动程序关联的kobject实例。该返回值可用于获取cdev实例。
	if (!p) {
		struct kobject *kobj;
		int idx;
		spin_unlock(&cdev_lock);
		kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
		if (!kobj)
			return -ENXIO;
		new = container_of(kobj, struct cdev, kobj);
		spin_lock(&cdev_lock);
		p = inode->i_cdev;
		if (!p) {
			inode->i_cdev = p = new;
			inode->i_cindex = idx;
			list_add(&inode->i_devices, &p->list);
			new = NULL;
		} else if (!cdev_get(p))
			ret = -ENXIO;
	} else if (!cdev_get(p))
		ret = -ENXIO;
	spin_unlock(&cdev_lock);
	cdev_put(new);
	if (ret)
		return ret;
	filp->f_op = fops_get(p->ops);
	if (!filp->f_op) {
		cdev_put(p);
		return -ENXIO;
	}
	if (filp->f_op->open) {
		lock_kernel();
		ret = filp->f_op->open(inode,filp);
		unlock_kernel();
	}
	if (ret)
		cdev_put(p);
	return ret;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	spin_unlock(&cdev_lock);
}

static void cdev_purge(struct cdev *cdev)
{
	spin_lock(&cdev_lock);
	while (!list_empty(&cdev->list)) {
		struct inode *inode;
		inode = container_of(cdev->list.next, struct inode, i_devices);
		list_del_init(&inode->i_devices);
		inode->i_cdev = NULL;
	}
	spin_unlock(&cdev_lock);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
const struct file_operations def_chr_fops = {
	.open = chrdev_open,
};

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct cdev *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct cdev *p = data;
	return cdev_get(p) ? 0 : -1;
}

/**
 * cdev_add() - add a char device to the system
 * @p: the cdev structure for the device
 * @dev: the first device number for which this device is responsible
 * @count: the number of consecutive minor numbers corresponding to this
 *         device
 *
 * cdev_add() adds the device represented by @p to the system, making it
 * live immediately.  A negative error code is returned on failure.
 */

//添加一个字符设备到系统
//p -- 
//dev -- 该设备对应的第一个设备编号
//count -- 表示该设备提供的从设备号的数量
// 	   -- 和该设备关联的从设备号的数目。count经常取1，但是在某些情况下，
//	   	会有多个设备编号对应于一个特定的设备。
//		例如，考虑SCSI磁带驱动程序，它通过每个物理设备的多个次设备号来允许
//		用户空间选择不同的操作模式(比如密度)。
//注意: 这个调用可能会失败。如果它返回一个负的错误码，则设备不会被添加到系统中。但这个调用几乎总会成功返回;
//只要cdev_add成功返回，我们的设备就"活"了，它的操作就会被内核调用。
//因此，驱动程序还没有完全准备好处理设备上的操作时，就不能调用cdev_add。

int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	p->dev = dev;
	p->count = count;
	return kobj_map(cdev_map, dev, count, NULL, exact_match, exact_lock, p);
}

static void cdev_unmap(dev_t dev, unsigned count)
{
	kobj_unmap(cdev_map, dev, count);
}

/**
 * cdev_del() - remove a cdev from the system
 * @p: the cdev structure to be removed
 *
 * cdev_del() removes @p from the system, possibly freeing the structure
 * itself.
 */
//从系统中移除一个字符设备
void cdev_del(struct cdev *p)
{
	cdev_unmap(p->dev, p->count);
	kobject_put(&p->kobj);
}


static void cdev_default_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
}

static void cdev_dynamic_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
	kfree(p);
}

static struct kobj_type ktype_cdev_default = {
	.release	= cdev_default_release,
};

static struct kobj_type ktype_cdev_dynamic = {
	.release	= cdev_dynamic_release,
};

/**
 * cdev_alloc() - allocate a cdev structure
 *
 * Allocates and returns a cdev structure, or NULL on failure.
 */
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kzalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		p->kobj.ktype = &ktype_cdev_dynamic;
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj);
	}
	return p;
}

/**
 * cdev_init() - initialize a cdev structure
 * @cdev: the structure to initialize
 * @fops: the file_operations for this device
 *
 * Initializes @cdev, remembering @fops, making it ready to add to the
 * system with cdev_add().
 */
//初始化一个struct cdev实例
void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	cdev->kobj.ktype = &ktype_cdev_default;
	kobject_init(&cdev->kobj);
	cdev->ops = fops;
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

void __init chrdev_init(void)
{
	cdev_map = kobj_map_init(base_probe, &chrdevs_lock);
	bdi_init(&directly_mappable_cdev_bdi);
}


/* Let modules do char dev stuff */
EXPORT_SYMBOL(register_chrdev_region);
EXPORT_SYMBOL(unregister_chrdev_region);
EXPORT_SYMBOL(alloc_chrdev_region);
EXPORT_SYMBOL(cdev_init);
EXPORT_SYMBOL(cdev_alloc);
EXPORT_SYMBOL(cdev_del);
EXPORT_SYMBOL(cdev_add);
EXPORT_SYMBOL(register_chrdev);
EXPORT_SYMBOL(unregister_chrdev);
EXPORT_SYMBOL(directly_mappable_cdev_bdi);
