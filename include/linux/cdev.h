#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H
#ifdef __KERNEL__

#include <linux/kobject.h>
#include <linux/kdev_t.h>
#include <linux/list.h>

struct file_operations;
struct inode;
struct module;

//ÿ���ַ��豸����ʾΪstruct cdev��һ��ʵ��(�豸���ݿ�)
struct cdev{
	struct kobject kobj;
	struct module *owner;//ָ���ṩ���������ģ��(����еĻ�)
	const struct file_operations *ops;//һ���ļ�������ʵ������Ӳ��ͨ�ŵľ������
	struct list_head list;//����ʵ��һ���������а������б�ʾ���豸���豸�����ļ���inode
	dev_t dev;//ָ�����豸��
	unsigned int count;//��ʾ����豸�����Ĵ��豸�ŵ���Ŀ
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
