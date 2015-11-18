#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)//ҳ����
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)//��ȡx������������ַ�ĺ�һ��PFNֵ
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)//��ȡx������������ַ�ĵ�ǰPFNֵ
#define PFN_PHYS(x)	((x) << PAGE_SHIFT)//����PFN��ֵΪxʱ����Ӧҳ֡����ʼ�����ַ

#endif
