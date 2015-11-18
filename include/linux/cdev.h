#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H
#ifdef __KERNEL__

#include <linux/kobject.h>
#include <linux/kdev_t.h>
#include <linux/list.h>

struct file_operations;
struct inode;
struct module;

//每个字符设备都表示为struct cdev的一个实例(设备数据库)
struct cdev{
	struct kobject kobj;
	struct module *owner;//指向提供驱动程序的模块(如果有的话)
	const struct file_operations *ops;//一组文件操作，实现了与硬件通信的具体操作
	struct list_head list;//用来实现一个链表，其中包含所有表示该设备的设备特殊文件的inode
	dev_t dev;//指定了设备号
	unsigned int count;//表示与该设备关联的从设备号的数目
};

void cdev_init(struct cdev *, const struct file_operations *);

struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);

int cdev_add(struct cdev *, dev_t, unsigned);

void cdev_del(struct cdev *);

void cd_forget(struct inode *);

extern struct backing_dev_info directly_mappable_cdev_bdi;

#endif
#endif
