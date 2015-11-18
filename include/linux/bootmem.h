/*
 * Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 */
#ifndef _LINUX_BOOTMEM_H
#define _LINUX_BOOTMEM_H

#include <linux/mmzone.h>
#include <asm/dma.h>

/*
 *  simple boot-time physical memory area allocator.
 */

extern unsigned long max_low_pfn;
extern unsigned long min_low_pfn;

/*
 * highest page
 */
extern unsigned long max_pfn;

#ifdef CONFIG_CRASH_DUMP
extern unsigned long saved_max_pfn;
#endif

/*
 * node_bootmem_map is a map pointer - the bits represent all physical 
 * memory pages (including holes) on the node.
 */
typedef struct bootmem_data {
	unsigned long node_boot_start;//起始页帧物理地址
	unsigned long node_low_pfn;//(低端内存)结束页帧的PFN
	void *node_bootmem_map;//位图起始地址(虚拟地址)
	unsigned long last_offset;//用来存放在前一次分配中所分配的最后一个字节相对于last_pos的位移量。这使得bootmem分配器可以分配小于一整页的内存区
	unsigned long last_pos;//用来存放前一次分配的最后一个页面相对于node_boot_start的页面号。这个域用在__alloc_bootmem_core()函数中，通过合并相邻的内存来减少内部碎片
	unsigned long last_success;	/* Previous allocation point.  To speed up searching */ //指定位图中上一次成功分配内存的位置，新的分配将由此开始。
	struct list_head list; //bdata_list链表结点
} bootmem_data_t;

extern unsigned long bootmem_bootmap_pages(unsigned long);
extern unsigned long init_bootmem(unsigned long addr, unsigned long memend);
extern void free_bootmem(unsigned long addr, unsigned long size);
extern void *__alloc_bootmem(unsigned long size,
			     unsigned long align,
			     unsigned long goal);
extern void *__alloc_bootmem_nopanic(unsigned long size,
				     unsigned long align,
				     unsigned long goal);
extern void *__alloc_bootmem_low(unsigned long size,
				 unsigned long align,
				 unsigned long goal);
extern void *__alloc_bootmem_low_node(pg_data_t *pgdat,
				      unsigned long size,
				      unsigned long align,
				      unsigned long goal);
extern void *__alloc_bootmem_core(struct bootmem_data *bdata,
				  unsigned long size,
				  unsigned long align,
				  unsigned long goal,
				  unsigned long limit);

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
extern void reserve_bootmem(unsigned long addr, unsigned long size);
//SMP_CACHE_BYTES会对齐数据，使之在大多数体系结构上能够理想地置于L1高速缓存中(尽管名字带SMP字样，但单处理器系统也会定义该常数)
//PAGE_SIZE将数据对齐到页边界
//PAGE_SIZE对齐方式适用于分配一个或多个整页，SMP_CACHE_BYTES在分配涉及部分页时能够产生更好的结果
#define alloc_bootmem(x) \
	__alloc_bootmem(x, SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low(x) \
	__alloc_bootmem_low(x, SMP_CACHE_BYTES, 0)
#define alloc_bootmem_pages(x) \
	__alloc_bootmem(x, PAGE_SIZE, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low_pages(x) \
	__alloc_bootmem_low(x, PAGE_SIZE, 0)
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

extern unsigned long free_all_bootmem(void);
extern unsigned long free_all_bootmem_node(pg_data_t *pgdat);
extern void *__alloc_bootmem_node(pg_data_t *pgdat,
				  unsigned long size,
				  unsigned long align,
				  unsigned long goal);
extern unsigned long init_bootmem_node(pg_data_t *pgdat,
				       unsigned long freepfn,
				       unsigned long startpfn,
				       unsigned long endpfn);
extern void reserve_bootmem_node(pg_data_t *pgdat,
				 unsigned long physaddr,
				 unsigned long size);
extern void free_bootmem_node(pg_data_t *pgdat,
			      unsigned long addr,
			      unsigned long size);

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
#define alloc_bootmem_node(pgdat, x) \
	__alloc_bootmem_node(pgdat, x, SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_pages_node(pgdat, x) \
	__alloc_bootmem_node(pgdat, x, PAGE_SIZE, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low_pages_node(pgdat, x) \
	__alloc_bootmem_low_node(pgdat, x, PAGE_SIZE, 0)
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

#ifdef CONFIG_HAVE_ARCH_ALLOC_REMAP
extern void *alloc_remap(int nid, unsigned long size);
#else
static inline void *alloc_remap(int nid, unsigned long size)
{
	return NULL;
}
#endif /* CONFIG_HAVE_ARCH_ALLOC_REMAP */

extern unsigned long __meminitdata nr_kernel_pages;
extern unsigned long __meminitdata nr_all_pages;

extern void *alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long limit);

#define HASH_EARLY	0x00000001	/* Allocating during early boot? */

/* Only NUMA needs hash distribution.
 * IA64 and x86_64 have sufficient vmalloc space.
 */
#if defined(CONFIG_NUMA) && (defined(CONFIG_IA64) || defined(CONFIG_X86_64))
#define HASHDIST_DEFAULT 1
#else
#define HASHDIST_DEFAULT 0
#endif
extern int hashdist;		/* Distribute hashes across NUMA nodes? */


#endif /* _LINUX_BOOTMEM_H */
