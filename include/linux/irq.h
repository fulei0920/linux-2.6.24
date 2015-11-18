#ifndef _LINUX_IRQ_H
#define _LINUX_IRQ_H

/*
 * Please do not include this file in generic code.  There is currently
 * no requirement for any architecture to implement anything held
 * within this file.
 *
 * Thanks. --rmk
 */

#include <linux/smp.h>

#ifndef CONFIG_S390

#include <linux/linkage.h>
#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/irqreturn.h>
#include <linux/errno.h>

#include <asm/irq.h>
#include <asm/ptrace.h>
#include <asm/irq_regs.h>

struct irq_desc;
//irq -- IRQ±àºÅ
//desc -- Ò»¸öÖ¸Ïò¸ºÔğ¸ÃÖĞ¶ÏµÄirq_handlerÊµÀıµÄÖ¸Õë
typedef	void fastcall (*irq_flow_handler_t)(unsigned int irq, struct irq_desc *desc);


/*
 * IRQ line status.
 *
 * Bits 0-7 are reserved for the IRQF_* bits in linux/interrupt.h
 *
 * IRQ types
 */
#define IRQ_TYPE_NONE		0x00000000	/* Default, unspecified type */
#define IRQ_TYPE_EDGE_RISING	0x00000001	/* Edge rising type */
#define IRQ_TYPE_EDGE_FALLING	0x00000002	/* Edge falling type */
#define IRQ_TYPE_EDGE_BOTH (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_EDGE_RISING)
#define IRQ_TYPE_LEVEL_HIGH	0x00000004	/* Level high type */
#define IRQ_TYPE_LEVEL_LOW	0x00000008	/* Level low type */
#define IRQ_TYPE_SENSE_MASK	0x0000000f	/* Mask of the above */
#define IRQ_TYPE_PROBE		0x00000010	/* Probing in progress */

/* Internal flags */
//ÔÚIRQ´¦Àí³ÌĞòÖ´ĞĞÆÚ¼ä£¬×´Ì¬ÉèÖÃÎªIRQ_INPROGRESS¡£ÓëIRQ_DISABLEDÀàËÆ£¬Õâ»á×èÖ¹ÆäÓàµÄÄÚºË´úÂëÖ´ĞĞ¸Ã´¦Àí³ÌĞò
#define IRQ_INPROGRESS		0x00000100	/* IRQ handler active - do not enter! */
//ÓÃÓÚ±íÊ¾±»Éè±¸Çı¶¯³ÌĞò½ûÓÃµÄIRQµçÂ·¡£¸Ã±êÖ¾Í¨ÖªÄÚºË²»Òª½øÈë´¦Àí³ÌĞò
#define IRQ_DISABLED		0x00000200	/* IRQ disabled - do not enter! */
//ÔÚCPU×¢Òâµ½Ò»¸öÖĞ¶Ïµ«ÉĞÎ´Ö´ĞĞ¶ÔÓ¦µÄ´¦Àí³ÌĞòÊ±£¬IRQ_PENDING±êÖ¾ÖÃÎ»
#define IRQ_PENDING		0x00000400	/* IRQ pending - replay on enable */
//ÒâÎ¶×Å¸ÃIRQÒÑ¾­½ûÓÃ£¬µ«´ËÇ°ÉĞÓĞÒ»¸öÎ´È·ÈÏµÄÖĞ¶Ï
#define IRQ_REPLAY		0x00000800	/* IRQ has been replayed but not acked yet */
//ÓÃÓÚIRQ×Ô¶¯¼ì²âºÍÅäÖÃ
#define IRQ_AUTODETECT		0x00001000	/* IRQ is being autodetected */
//ÓÃÓÚIRQ×Ô¶¯¼ì²âºÍÅäÖÃ
#define IRQ_WAITING		0x00002000	/* IRQ not yet seen - for autodetection */
//ÓÃÓÚAlphaºÍPowerPCÏµÍ³£¬ÓÃÓÚÇø·ÖµçÆ½´¥·¢ºÍ±ßÑØ´¥·¢µÄIRQ
#define IRQ_LEVEL		0x00004000	/* IRQ level triggered */
//ÎªÕıÈ·´¦Àí·¢ÉúÔÚÖĞ¶Ï´¦ÀíÆÚ¼äµÄÖĞ¶Ï£¬ĞèÒªIRQ_MASKED±êÖ¾
#define IRQ_MASKED		0x00008000	/* IRQ masked - shouldn't be seen again */
//ÔÚÄ³¸öIRQÖ»ÄÜ·¢ÉúÔÚÒ»¸öCPUÉÏÊ±£¬½«ÉèÖÃIRQ_PER_CPU±êÖ¾Î»¡£
//(ÔÚSMPÏµÍ³ÖĞ£¬¸Ã±êÖ¾Ê¹¼¸¸öÓÃÓÚ·ÀÖ¹²¢·¢·ÃÎÊµÄ±£»¤»úÖÆ±äµÃ¶àÓà)
#define IRQ_PER_CPU		0x00010000	/* IRQ is per CPU */
#define IRQ_NOPROBE		0x00020000	/* IRQ is not valid for probing */
//Èç¹ûµ±Ç°IRQ¿ÉÒÔÓÉ¶à¸öÉè±¸¹²Ïí£¬²»ÊÇ×¨ÊôÓÚÄ³Ò»Éè±¸£¬ÔòÉèÖÃIRQ_NOREQUEST±êÖ¾
#define IRQ_NOREQUEST		0x00040000	/* IRQ cannot be requested */
#define IRQ_NOAUTOEN		0x00080000	/* IRQ will not be enabled on request irq */
#define IRQ_WAKEUP		0x00100000	/* IRQ triggers system wakeup */
#define IRQ_MOVE_PENDING	0x00200000	/* need to re-target IRQ destination */
#define IRQ_NO_BALANCING	0x00400000	/* IRQ is excluded from balancing */

#ifdef CONFIG_IRQ_PER_CPU
# define CHECK_IRQ_PER_CPU(var) ((var) & IRQ_PER_CPU)
# define IRQ_NO_BALANCING_MASK	(IRQ_PER_CPU | IRQ_NO_BALANCING)
#else
# define CHECK_IRQ_PER_CPU(var) 0
# define IRQ_NO_BALANCING_MASK	IRQ_NO_BALANCING
#endif

struct proc_dir_entry;
struct msi_desc;

/**
 * struct irq_chip - hardware interrupt chip descriptor
 *
 * @name:		name for /proc/interrupts
 * @startup:		start up the interrupt (defaults to ->enable if NULL)
 * @shutdown:		shut down the interrupt (defaults to ->disable if NULL)
 * @enable:		enable the interrupt (defaults to chip->unmask if NULL)
 * @disable:		disable the interrupt (defaults to chip->mask if NULL)
 * @ack:		start of a new interrupt
 * @mask:		mask an interrupt source
 * @mask_ack:		ack and mask an interrupt source
 * @unmask:		unmask an interrupt source
 * @eoi:		end of interrupt - chip level
 * @end:		end of interrupt - flow level
 * @set_affinity:	set the CPU affinity on SMP machines
 * @retrigger:		resend an IRQ to the CPU
 * @set_type:		set the flow type (IRQ_TYPE_LEVEL/etc.) of an IRQ
 * @set_wake:		enable/disable power-management wake-on of an IRQ
 *
 * @release:		release function solely used by UML
 * @typename:		obsoleted by name, kept as migration helper
 */
//¸ÃÀàĞÍ³éÏó³öÁËÒ»¸öIRQ¿ØÖÆÆ÷µÄ¾ßÌåÌØÕ÷£¬¿ÉÓÃÓÚÄÚºËµÄÌåÏµ»ú¹¹ÎŞ¹Ø²¿·Ö¡£
//ËüÌá¹©µÄº¯ÊıÓÃÓÚ¸Ä±äIRQµÄ×´Ì¬£¬ÕâÒ²ÊÇËüÃÇ»¹¸ºÔğÉèÖÃflagµÄÔ­Òò
//¸Ã½á¹¹ĞèÒª¿¼ÂÇÄÚºËÖĞ³öÏÖµÄ¸÷¸öIRQÊµÏÖµÄËùÓĞÌØĞÔ¡£
//Òò¶ø£¬Ò»¸ö¸Ã½á¹¹µÄÌØ¶¨ÊµÀı£¬Í¨³£Ö»¶¨ÒåËùÓĞ¿ÉÄÜ·½·¨µÄÒ»¸ö×Ó¼¯
struct irq_chip {
	//ÓÃÓÚ±êÊ¶Ó²¼ş¿ØÖÆÆ÷¡£
	//ÔÚIA-32ÏµÍ³ÉÏ¿ÉÄÜµÄÖµÊÇ"XTPIC"ºÍ"IO-APIC"£¬ÔÚAMD64ÏµÍ³ÉÏ´ó¶àÊıÇé¿öÏÂÒ²»áÊ¹ÓÃºóÕß¡£
	//ÔÚÆäËûÏµÍ³ÉÏÓĞ¸÷ÖÖ¸÷ÑùµÄÖµ¡£
	const char	*name;
	//ÓÃÓÚµÚÒ»´Î³õÊ¼»¯Ò»¸öIRQ¡£ÔÚ´ó¶àÊıÇé¿öÏÂ£¬³õÊ¼»¯¹¤×÷½öÏŞÓÚÆôÓÃ¸ÃIRQ
	//Òò¶ø£¬startupº¯ÊıÊµ¼ÊÉÏ¾ÍÊÇ½«¹¤×÷×ª¸øenable¡£
	unsigned int	(*startup)(unsigned int irq);
	//ÍêÈ«¹Ø±ÕÒ»¸öÖĞ¶ÏÔ´¡£
	//Èç¹û²»Ö§³Ö¸ÃÌØĞÔ£¬ÄÇÃ´Õâ¸öº¯ÊıÊµ¼ÊÉÏÊÇdisableµÄ±ğÃû
	void		(*shutdown)(unsigned int irq);
	//¼¤»îÒ»¸öIRQ.
	//»»¾ä»°Ëµ£¬ËüÖ´ĞĞIRQÓÉ½ûÓÃ×´Ì¬µ½ÆôÓÃ×´Ì¬µÄ×ª»»¡£
	//Îª´Ë£¬±ØĞëÏòI/OÄÚ´æ»òI/O¶Ë¿ÚÖĞÓ²¼şÏà¹ØµÄÎ»ÖÃĞ´ÈëÌØ¶¨ÓÚÓ²¼şµÄÊıÖµ
	void		(*enable)(unsigned int irq);
	//ÓëenableÏà¶ÔÓ¦£¬ÓÃÓÚ½ûÓÃIRQ¡£
	void		(*disable)(unsigned int irq);
	//ackÓëÖĞ¶Ï¿ØÖÆÆ÷µÄÓ²¼şÃÜÇĞÏà¹Ø¡£ÔÚÄ³Ğ©Ä£ĞÍÖĞ£¬IRQÇëÇóµÄµ½´ï
	//(ÒÔ¼°ÔÚ´¦ÀíÆ÷µÄ¶ÔÓ¦ÖĞ¶Ï)±ØĞëÏÔÊ¾È·ÈÏ£¬ºóĞøµÄÇëÇó²ÅÄÜ½øĞĞ´¦Àí¡£
	//Èç¹ûĞ¾Æ¬×éÃ»ÓĞÕâÑùµÄÒªÇó£¬¸ÃÖ¸Õë¿ÉÒÔÖ¸ÏòÒ»¸ö¿Õº¯Êı£¬»òNULLÖ¸Õë¡£
	void		(*ack)(unsigned int irq);
	void		(*mask)(unsigned int irq);
	//È·ÈÏÒ»¸öÖĞ¶Ï£¬²¢ÔÚ½ÓÏÂÀ´ÆÁ±Î¸ÃÖĞ¶Ïå
	void		(*mask_ack)(unsigned int irq);
	void		(*unmask)(unsigned int irq);
	//ÏÖ´úµÄÖĞ¶Ï¿ØÖÆÆ÷²»ĞèÒªÄÚºË½øĞĞÌ«¶àµÄµçÁ÷¿ØÖÆ£¬¿ØÖÆÆ÷¼¸ºõ¿ÉÒÔ¹ÜÀíËùÓĞÊÂÎñ¡£
	//ÔÚ´¦ÀíÖĞ¶ÏÊ±ĞèÒªÒ»¸öµ½Ó²¼şµÄ»Øµ÷£¬ÓÉeoiÌá¹©£¬eoi±íÊ¾end of interrupt£¬¼´ÖĞ¶Ï½áÊø
	void		(*eoi)(unsigned int irq);

	//±ê¼ÇÖĞ¶Ï´¦ÀíÔÚµçÁ÷²ã´ÎµÄ½áÊø¡£
	//Èç¹ûÒ»¸öÖĞ¶ÏÔÚÖĞ¶Ï´¦ÀíÆÚ¼ä±»½ûÓÃ£¬ÄÇÃ´¸Ãº¯Êı¸ºÔğÖØĞÂÆôÓÃ´ËÀàÖĞ¶Ï
	void		(*end)(unsigned int irq);
	//ÔÚ¶à´¦ÀíÆ÷ÏµÍ³ÖĞ£¬¿ÉÒÔÊ¹ÓÃset_affinityÖ¸¶¨CPUÀ´´¦ÀíÌØ¶¨µÄIRQ.
	//ÕâÊ¹µÃ¿ÉÒÔ½«IRQ·ÖÅä¸øÄ³Ğ©CPU(Í¨³££¬SMPÏµÍ³ÉÏµÄIRQÊÇÆ½¾Ö·¢²¼µ½ËùÓĞ´¦ÀíÆ÷µÄ)¡£
	//¸Ã·½·¨ÔÚµ¥´¦ÀíÆ÷ÏµÍ³ÉÏÃ»ÓÃ£¬¿ÉÒÔÉèÖÃÎªNULLÖ¸Õë
	void		(*set_affinity)(unsigned int irq, cpumask_t dest);
	int		(*retrigger)(unsigned int irq);
	//ÉèÖÃIRQµÄµçÁ÷ÀàĞÍ¡£
	//¸Ã·½·¨Ö÷ÒªÊ¹ÓÃÔÚARM¡¢PowerPCºÍSuperH»úÆ÷ÉÏ£¬ÆäËûÏµÍ³²»ĞèÒª¸Ã·½·¨£¬¿ÉÒÔÉèÖÃÎªNULL
	int		(*set_type)(unsigned int irq, unsigned int flow_type);
	int		(*set_wake)(unsigned int irq, unsigned int on);

	/* Currently used only by UML, might disappear one day.*/
#ifdef CONFIG_IRQ_RELEASE_METHOD
	void		(*release)(unsigned int irq, void *dev_id);
#endif
	/*
	 * For compatibility, ->typename is copied into ->name.
	 * Will disappear.
	 */
	const char	*typename;//ÎªÁË¼æÈİĞÔ¶øÊ¹ÓÃ
};

/**
 * struct irq_desc - interrupt descriptor
 *
 * @handle_irq:		highlevel irq-events handler [if NULL, __do_IRQ()]
 * @chip:		low level interrupt hardware access
 * @msi_desc:		MSI descriptor
 * @handler_data:	per-IRQ data for the irq_chip methods
 * @chip_data:		platform-specific per-chip private data for the chip
 *			methods, to allow shared chip implementations
 * @action:		the irq action chain
 * @status:		status information
 * @depth:		disable-depth, for nested irq_disable() calls
 * @wake_depth:		enable depth, for multiple set_irq_wake() callers
 * @irq_count:		stats field to detect stalled irqs
 * @irqs_unhandled:	stats field for spurious unhandled interrupts
 * @last_unhandled:	aging timer for unhandled count
 * @lock:		locking for SMP
 * @affinity:		IRQ affinity on SMP
 * @cpu:		cpu index useful for balancing
 * @pending_mask:	pending rebalanced interrupts
 * @dir:		/proc/irq/ procfs entry
 * @affinity_entry:	/proc/irq/smp_affinity procfs entry on SMP
 * @name:		flow handler name for /proc/interrupts output
 */
//¶ÔÓÚÃ¿¸öIRQÖĞ¶ÏÏß£¬Linux¶¼ÓÃÒ»¸öirq_desc_tÊı¾İ½á¹¹À´ÃèÊö£¬ÎÒÃÇ°ÑËü½Ğ×öIRQÃèÊö·û
struct irq_desc
{
	//µçÁ÷²ãISRÓÉhandle_irqÌá¹©¡£
	//Ã¿µ±·¢ÉúÖĞ¶ÏÊ±£¬ÌØ¶¨ÓÚÌåÏµ½á¹¹µÄ´úÂë¶¼»áµ÷ÓÃhandle_irq¡£
	//¸Ãº¯Êı¸ºÔğÊ¹ÓÃchipÖĞÌá¹©µÄÌØ¶¨ÓÚ¿ØÖÆÆ÷µÄ·½·¨£¬½øĞĞ´¦ÀíÖĞ¶ÏËù±ØĞëµÄÒ»Ğ©µ×²ã²Ù×÷¡£
	irq_flow_handler_t	handle_irq;
	//µçÁ÷´¦ÀíºÍĞ¾Æ¬Ïà¹Ø²Ù×÷±»·â×°ÔÚchipÖĞ¡£
	struct irq_chip		*chip;
	struct msi_desc		*msi_desc;
	//¿ÉÒÔÖ¸ÏòÈÎÒâÊı¾İ£¬¸ÃÊı¾İ¿ÉÒÔÊÇÌØ¶¨ÓÚIRQ»ò´¦Àí³ÌĞòµÄ¡£
	void			*handler_data;
	//Ö¸Ïò¿ÉÄÜÓëchipÏà¹ØµÄÈÎÒâÊı¾İ
	void			*chip_data;
	//Ìá¹©ÁËÒ»¸ö²Ù×÷Á´£¬ĞèÒªÔÚÖĞ¶Ï·¢ÉúÊ±Ö´ĞĞ¡£
	//ÓÉÖĞ¶ÏÍ¨ÖªµÄÉè±¸Çı¶¯³ÌĞò£¬¿ÉÒÔ½«ÓëÖ®Ïà¹ØµÄ´¦Àí³ÌĞòº¯Êı·ÅÖÃÔÚ´Ë´¦
	struct irqaction	*action;	/* IRQ action list */
	//ÃèÊöÁËIRQµÄµ±Ç°×´Ì¬¡£
	//¸ù¾İstatusµ±Ç°Öµ£¬ÄÚºËºÜÈİÒ×»òÕßÄ³¸öIRQµÄ×´Ì¬£¬¶øÎŞĞëÁË½âµ×²ãÊµÏÖµÄÓ²¼şÏà¹ØÌØĞÔ¡£
	//µ±È»Ö»ÉèÖÃ¶ÔÓ¦µÄ±êÖ¾Î»ÊÇ²»»á²úÉúÔ¤ÆÚĞ§¹ûµÄ£¬»¹±ØĞë½«ĞÂ×´Ì¬Í¨Öªµ×²ãÓ²¼ş¡£
	//Òò¶ø£¬¸Ã±êÖ¾Ö»ÄÜÍ¨¹ıÌØ¶¨ÓÚ¿ØÖÆÆ÷µÄº¯ÊıÉèÖÃ£¬ÕâĞ©º¯ÊıÍ¬Ê±»¹¸ºÔğ½«ÉèÖÃĞÅÏ¢Í¬²½µ½µ×²ãÓ²¼ş¡£
	//ÔÚºÜ¶àÇé¿öÏÂ£¬Õâ±ØĞëÊ¹ÓÃ»ã±àÓïÑÔ´úÂë£¬»òÍ¨¹ıoutÃüÁîÏòÌØ¶¨µØÖ·Ğ´ÈëÌØ¶¨ÊıÖµ¡£
	unsigned int		status;		/* IRQ status */

	//ÓÃÓÚÈ·¶¨IRQµçÂ·ÊÇÆôÓÃµÄ»¹ÊÇ½ûÓÃµÄ¡£ÕıÖµ±íÊ¾½ûÓÃ£¬¶ø0±íÊ¾ÆôÓÃ
	//ÎªÊ²Ã´ÓÃÕıÖµ±íÊ¾½ûÓÃIRQÄØå ÒòÎªÕâÊ¹µÃÄÚºËÄÜ¹»Çø·ÖÆôÓÃºÍ½ûÓÃµÄIRQµçÂ·£¬
	//ÒÔ¼°ÖØ¸´½ûÓÃÍ¬Ò»ÖĞ¶ÏµÄÇéĞÎ¡£Õâ¸öÖµÏàµ±ÓÚÒ»¸ö¼ÆÊıÆ÷£¬ÄÚºËÆäÓà²¿·ÖµÄ´úÂë
	//Ã¿´Î½ûÓÃÄ³¸öÖĞ¶Ï£¬Ôò½«¶ÔÓ¦µÄ¼ÆÊıÆ÷¼Ó1£»Ã¿´ÎÖĞ¶Ï±»ÔÙ´ÎÆôÓÃ£¬Ôò½«¼ÆÊıÆ÷¼õ1¡£
	//µ±depth¹é0Ê±£¬Ó²¼ş²ÅÄÜÔÙ´ÎÊ¹ÓÃ¶ÔÓ¦µÄIRQ¡£ÕâÖÖ·½·¨ÄÜ¹»Ö§³Ö¶ÔÇ¶Ì×½ûÓÃÖĞ¶ÏµÄÕıÈ·´¦Àí¡£
	unsigned int		depth;		/* nested irq disables */
	unsigned int		wake_depth;	/* nested wake enables */
	unsigned int		irq_count;	/* For detecting broken IRQs */
	unsigned int		irqs_unhandled;
	unsigned long		last_unhandled;	/* Aging timer for unhandled count */
	spinlock_t		lock;
#ifdef CONFIG_SMP
	cpumask_t		affinity;
	unsigned int		cpu;
#endif
#if defined(CONFIG_GENERIC_PENDING_IRQ) || defined(CONFIG_IRQBALANCE)
	cpumask_t		pending_mask;
#endif
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*dir;
#endif
	//Ö¸¶¨ÁËµçÁ÷²ã´¦Àí³ÌĞòµÄÃû³Æ£¬½«ÏÔÊ¾ÔÚ/proc/interruptsÖĞ¡£
	//¶Ô±ßÑØ´¥·¢ÖĞ¶Ï£¬Í¨³£ÊÇÊÇ"edge"£¬¶ÔµçÆ½´¥·¢ÖĞ¶Ï£¬Í¨³£ÊÇ"level"
	const char		*name;
} ____cacheline_internodealigned_in_smp;

extern struct irq_desc irq_desc[NR_IRQS];

/*
 * Migration helpers for obsolete names, they will go away:
 */
#define hw_interrupt_type	irq_chip //ÎªÁË¼æÈİIRQ×ÓÏµÍ³µÄÇ°Ò»°æ±¾
typedef struct irq_chip		hw_irq_controller;
#define no_irq_type		no_irq_chip
typedef struct irq_desc		irq_desc_t;

/*
 * Pick up the arch-dependent methods:
 */
#include <asm/hw_irq.h>

extern int setup_irq(unsigned int irq, struct irqaction *new);

#ifdef CONFIG_GENERIC_HARDIRQS

#ifndef handle_dynamic_tick
# define handle_dynamic_tick(a)		do { } while (0)
#endif

#ifdef CONFIG_SMP

#if defined(CONFIG_GENERIC_PENDING_IRQ) || defined(CONFIG_IRQBALANCE)

void set_pending_irq(unsigned int irq, cpumask_t mask);
void move_native_irq(int irq);
void move_masked_irq(int irq);

#else /* CONFIG_GENERIC_PENDING_IRQ || CONFIG_IRQBALANCE */

static inline void move_irq(int irq)
{
}

static inline void move_native_irq(int irq)
{
}

static inline void move_masked_irq(int irq)
{
}

static inline void set_pending_irq(unsigned int irq, cpumask_t mask)
{
}

#endif /* CONFIG_GENERIC_PENDING_IRQ */

extern int irq_set_affinity(unsigned int irq, cpumask_t cpumask);
extern int irq_can_set_affinity(unsigned int irq);

#else /* CONFIG_SMP */

#define move_native_irq(x)
#define move_masked_irq(x)

static inline int irq_set_affinity(unsigned int irq, cpumask_t cpumask)
{
	return -EINVAL;
}

static inline int irq_can_set_affinity(unsigned int irq) { return 0; }

#endif /* CONFIG_SMP */

#ifdef CONFIG_IRQBALANCE
extern void set_balance_irq_affinity(unsigned int irq, cpumask_t mask);
#else
static inline void set_balance_irq_affinity(unsigned int irq, cpumask_t mask)
{
}
#endif

#ifdef CONFIG_AUTO_IRQ_AFFINITY
extern int select_smp_affinity(unsigned int irq);
#else
static inline int select_smp_affinity(unsigned int irq)
{
	return 1;
}
#endif

extern int no_irq_affinity;

static inline int irq_balancing_disabled(unsigned int irq)
{
	return irq_desc[irq].status & IRQ_NO_BALANCING_MASK;
}

/* Handle irq action chains: */
extern int handle_IRQ_event(unsigned int irq, struct irqaction *action);

/*
 * Built-in IRQ handlers for various IRQ types,
 * callable via desc->chip->handle_irq()
 */
extern void fastcall handle_level_irq(unsigned int irq, struct irq_desc *desc);
extern void fastcall handle_fasteoi_irq(unsigned int irq, struct irq_desc *desc);
extern void fastcall handle_edge_irq(unsigned int irq, struct irq_desc *desc);
extern void fastcall handle_simple_irq(unsigned int irq, struct irq_desc *desc);
extern void fastcall handle_percpu_irq(unsigned int irq, struct irq_desc *desc);
extern void fastcall handle_bad_irq(unsigned int irq, struct irq_desc *desc);

/*
 * Monolithic do_IRQ implementation.
 * (is an explicit fastcall, because i386 4KSTACKS calls it from assembly)
 */
#ifndef CONFIG_GENERIC_HARDIRQS_NO__DO_IRQ
extern fastcall unsigned int __do_IRQ(unsigned int irq);
#endif

/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt. If the descriptor is attached to an
 * irqchip-style controller then we call the ->handle_irq() handler,
 * and it calls __do_IRQ() if it's attached to an irqtype-style controller.
 */
static inline void generic_handle_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_desc + irq;

#ifdef CONFIG_GENERIC_HARDIRQS_NO__DO_IRQ
	desc->handle_irq(irq, desc);
#else
	if (likely(desc->handle_irq))
		desc->handle_irq(irq, desc);
	else
		__do_IRQ(irq);
#endif
}

/* Handling of unhandled and spurious interrupts: */
extern void note_interrupt(unsigned int irq, struct irq_desc *desc,
			   int action_ret);

/* Resending of interrupts :*/
void check_irq_resend(struct irq_desc *desc, unsigned int irq);

/* Enable/disable irq debugging output: */
extern int noirqdebug_setup(char *str);

/* Checks whether the interrupt can be requested by request_irq(): */
extern int can_request_irq(unsigned int irq, unsigned long irqflags);

/* Dummy irq-chip implementations: */
extern struct irq_chip no_irq_chip;
extern struct irq_chip dummy_irq_chip;

extern void
set_irq_chip_and_handler(unsigned int irq, struct irq_chip *chip,
			 irq_flow_handler_t handle);
extern void
set_irq_chip_and_handler_name(unsigned int irq, struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name);

extern void
__set_irq_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
		  const char *name);

/* caller has locked the irq_desc and both params are valid */
static inline void __set_irq_handler_unlocked(int irq,
					      irq_flow_handler_t handler)
{
	irq_desc[irq].handle_irq = handler;
}

/*
 * Set a highlevel flow handler for a given IRQ:
 */
//ÎªÄ³¸ö¸ø¶¨µÄIRQ±àºÅÉèÖÃµçÁ÷´¦Àí³ÌĞò
static inline void
set_irq_handler(unsigned int irq, irq_flow_handler_t handle)
{
	__set_irq_handler(irq, handle, 0, NULL);
}

/*
 * Set a highlevel chained flow handler for a given IRQ.
 * (a chained handler is automatically enabled and set to
 *  IRQ_NOREQUEST and IRQ_NOPROBE)
 */
//ÎªÄ³¸ö¸ø¶¨µÄIRQ±àºÅÉèÖÃµçÁ÷´¦Àí³ÌĞò£¬´¦Àí³ÌĞò±ØĞë´¦Àí¹²ÏíµÄÖĞ¶Ï¡£
//Õâ»áÉèÖÃirq_desc[irq]->statusÖĞµÄ±êÖ¾Î»IRQ_NOREQUESTºÍIRQ_NOPROBE
static inline void
set_irq_chained_handler(unsigned int irq,
			irq_flow_handler_t handle)
{
	__set_irq_handler(irq, handle, 1, NULL);
}

/* Handle dynamic irq creation and destruction */
extern int create_irq(void);
extern void destroy_irq(unsigned int irq);

/* Test to see if a driver has successfully requested an irq */
static inline int irq_has_action(unsigned int irq)
{
	struct irq_desc *desc = irq_desc + irq;
	return desc->action != NULL;
}

/* Dynamic irq helper functions */
extern void dynamic_irq_init(unsigned int irq);
extern void dynamic_irq_cleanup(unsigned int irq);

/* Set/get chip/data for an IRQ: */
extern int set_irq_chip(unsigned int irq, struct irq_chip *chip);
extern int set_irq_data(unsigned int irq, void *data);
extern int set_irq_chip_data(unsigned int irq, void *data);
extern int set_irq_type(unsigned int irq, unsigned int type);
extern int set_irq_msi(unsigned int irq, struct msi_desc *entry);

#define get_irq_chip(irq)	(irq_desc[irq].chip)
#define get_irq_chip_data(irq)	(irq_desc[irq].chip_data)
#define get_irq_data(irq)	(irq_desc[irq].handler_data)
#define get_irq_msi(irq)	(irq_desc[irq].msi_desc)

#endif /* CONFIG_GENERIC_HARDIRQS */

#endif /* !CONFIG_S390 */

#endif /* _LINUX_IRQ_H */
