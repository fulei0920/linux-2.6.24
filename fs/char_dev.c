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

//�����ַ��豸�����ݿ�
//ɢ�б�ʹ�����豸����Ϊɢ�м�
//ɢ�з����൱��:major % 255
static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

//ֻ�����ַ��豸���豸�����ݿ�
//���ڹ���Ϊ�������������豸�ŷ�Χ
//���������������һ����̬���豸�ţ�����ָ��һ����Χ�����л�ȡ
//ʹ��ɢ�б��������ѷ�����豸�ŷ�Χ��ʹ�����豸����Ϊɢ�м�
//ע�⣬�ں˲�����Ϊÿһ���ַ��豸��Ŷ���һ�� char_device_struct �ṹ������Ϊһ���Ӧͬһ���ַ��豸�������豸��ŷ�Χ����һ������(����ŷ�Χ����ʱ)char_device_struct �ṹ��
static struct char_device_struct {
	struct char_device_struct *next;//����ͬһɢ�����е�����ɢ��Ԫ��
	unsigned int major;//ָ�������豸��
	unsigned int baseminor;//����minorct�����豸�ŵ�������Χ����С�Ĵ��豸��
	int minorct;
	char name[64];//Ϊ���豸�ṩ��һ����ʶ��
	struct file_operations *fops;//ָ������豸������file_operationsʵ��
	struct cdev *cdev;		/* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

/* index in the above */
//�������豸�ż���ɢ��λ��
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
	//���������豸��ŷ�Χ�����豸��Ϊ 0����ô��ʾ�豸������������̬����һ�����豸�š�
	//��̬�������豸�ŵ�ԭ���Ǵ�ɢ�б�����һ��Ͱ��ǰѰ�ң��Ǹ�Ͱ�ǿյģ����豸�ž�����Ӧɢ��Ͱ����š�
	//���Զ�̬��������豸������С�� 256�����ÿ��Ͱ�����ַ��豸����ˣ��Ƕ�̬����ͻ�ʧ�ܡ�
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
		//ͬһ��ɢ��Ͱ�е��ַ��豸��ŷ�Χ�����豸�ŵ�������ġ�
		//ͬһ��ɢ��Ͱ�е��ַ��豸��ŷ�Χ�ǰ���ʼ���豸�ŵ�������ġ�
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

//����һ�������������豸���
//from -- ���������豸��ŷ�Χ����ʼֵ��from�Ĵ��豸�ž�������Ϊ0�����Ըú������������Ǳ���ġ�
//count -- ��������������豸��ŵĸ�����ע�⣬���count�ǳ�����������ķ�Χ���ܺ���һ�����豸���ص���
//		��ֻҪ����������ı�ŷ�Χ�ǿ��õģ��򲻻�����κ����⡣
//name -- �͸ñ�ŷ�Χ�������豸���ƣ�����������/proc/devices��sysfs��
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
//��̬�����豸��š������������û�м�鷶Χ��������(��Խ������豸��)��������̬���������Ҹ��յ�ɢ��Ͱ����������Ҳ����
//��̬�����ȱ����:���ڷ�������豸�Ų��ܱ�֤ʼ��һ�£������޷�Ԥ�ȴ����豸�ڵ㡣
//�������������һ���÷����⵹����ʲô���⣬��Ϊһ���������豸�ţ��Ϳ��Դ�/proc/devices�ж�ȡ�õ���
//dev -- ����������Ĳ������ڳɹ���ɵ��ú󽫱����ѷ��䷶Χ�ĵ�һ����š�
//baseminor -- Ҫʹ�õı�����ĵ�һ�����豸�ţ���ͨ����0��
//count -- ��������������豸��ŵĸ�����ע�⣬���count�ǳ�����������ķ�Χ���ܺ���һ�����豸���ص���
//		��ֻҪ����������ı�ŷ�Χ�ǿ��õģ��򲻻�����κ����⡣
//name -- �͸ñ�ŷ�Χ�������豸���ƣ�����������/proc/devices��sysfs��
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
//һ����ʽ�����豸��ŷ�Χ�ĺ�����
//������һ���������豸�ź� 0 ~ 255 �Ĵ��豸�ŷ�Χ��
//�����������豸��Ϊ 0 ��̬����һ����
//�ú������贫��һ�� file_operations �ṹ��ָ�룬�����ڲ��Զ�������һ���µ�cdev�ṹ��
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
//�ͷ��豸���
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
//���ڴ��ַ��豸��ͨ�ú���
int chrdev_open(struct inode * inode, struct file * filp)
{
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	spin_lock(&cdev_lock);
	p = inode->i_cdev;
	//�ٶ���ʾ�豸�ļ���inode��ǰû�д򿪹������ݳ��ε��豸�ţ�
	//kobject_lookup��ѯ�ַ��豸�����ݿ⣬����������������������kobjectʵ�����÷���ֵ�����ڻ�ȡcdevʵ����
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

//���һ���ַ��豸��ϵͳ
//p -- 
//dev -- ���豸��Ӧ�ĵ�һ���豸���
//count -- ��ʾ���豸�ṩ�Ĵ��豸�ŵ�����
// 	   -- �͸��豸�����Ĵ��豸�ŵ���Ŀ��count����ȡ1��������ĳЩ����£�
//	   	���ж���豸��Ŷ�Ӧ��һ���ض����豸��
//		���磬����SCSI�Ŵ�����������ͨ��ÿ�������豸�Ķ�����豸��������
//		�û��ռ�ѡ��ͬ�Ĳ���ģʽ(�����ܶ�)��
//ע��: ������ÿ��ܻ�ʧ�ܡ����������һ�����Ĵ����룬���豸���ᱻ��ӵ�ϵͳ�С���������ü����ܻ�ɹ�����;
//ֻҪcdev_add�ɹ����أ����ǵ��豸��"��"�ˣ����Ĳ����ͻᱻ�ں˵��á�
//��ˣ���������û����ȫ׼���ô����豸�ϵĲ���ʱ���Ͳ��ܵ���cdev_add��

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
//��ϵͳ���Ƴ�һ���ַ��豸
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
//��ʼ��һ��struct cdevʵ��
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
