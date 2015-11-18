/*
 *  linux/fs/ext2/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 */

#include "ext2.h"
#include "xattr.h"
#include <linux/namei.h>

static void *ext2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext2_inode_info *ei = EXT2_I(dentry->d_inode);
	nd_set_link(nd, (char *)ei->i_data);
	return NULL;
}

//普通符号链接的目标文件路径大于60，需要根据i_block数组中的数据块地址读取目标文件路径。
//ext2_symlink_inode_operations比ext2_fast_symlink_inode_operations多了一个put_link函数，
//这是由于普通符号链接需要使用数据块，因此follow_link函数需要把数据块中的内容读取出来，
//放到一个内存中，当处理完成时，put_link负责释放内存
const struct inode_operations ext2_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};

//对于一个普通文件的定位步骤是，
const struct inode_operations ext2_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext2_follow_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};
