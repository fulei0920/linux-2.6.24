#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)//页对齐
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)//获取x所代表的物理地址的后一个PFN值
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)//获取x所代表的物理地址的当前PFN值
#define PFN_PHYS(x)	((x) << PAGE_SHIFT)//返回PFN的值为x时所对应页帧的起始物理地址

#endif
