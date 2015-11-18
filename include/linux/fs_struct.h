#ifndef _LINUX_FS_STRUCT_H
#define _LINUX_FS_STRUCT_H

struct dentry;
struct vfsmount;


//fs_struct�����˽��̵��ļ�ϵͳ�������
struct fs_struct 
{
	//�ṹ��ʹ�ü���
	atomic_t count;	
	//�����ýṹ�����
	rwlock_t lock;	
	//Ĭ�ϵ��ļ�����Ȩ��, ����ʾ��Ҫ�ڴ򿪵��ļ������õ����Ȩ
	//��׼�����룬�����������ļ���Ȩ��
	//��ֵ����ʹ��umask�����ȡ�����á����ڲ���ͬ����ϵͳ�������
	int umask;		
	//���̸�Ŀ¼��Ŀ¼�����
	struct dentry * root;	
	//���̵�ǰ����Ŀ¼��Ŀ¼�����
	struct dentry * pwd;	
	//�ɹ�ѡ��ĸ�Ŀ¼��Ŀ¼�����
	struct dentry * altroot;	
	//��Ŀ¼�İ�װ�����
	struct vfsmount * rootmnt;	
	//pwd�İ�װ�����
	struct vfsmount * pwdmnt;	
	//�ɹ�ѡ��ĸ�Ŀ¼�İ�װ�����
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
