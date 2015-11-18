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
//irq -- IRQ���
//desc -- һ��ָ������жϵ�irq_handlerʵ����ָ��
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
//��IRQ�������ִ���ڼ䣬״̬����ΪIRQ_INPROGRESS����IRQ_DISABLED���ƣ������ֹ������ں˴���ִ�иô������
#define IRQ_INPROGRESS		0x00000100	/* IRQ handler active - do not enter! */
//���ڱ�ʾ���豸����������õ�IRQ��·���ñ�־֪ͨ�ں˲�Ҫ���봦�����
#define IRQ_DISABLED		0x00000200	/* IRQ disabled - do not enter! */
//��CPUע�⵽һ���жϵ���δִ�ж�Ӧ�Ĵ������ʱ��IRQ_PENDING��־��λ
#define IRQ_PENDING		0x00000400	/* IRQ pending - replay on enable */
//��ζ�Ÿ�IRQ�Ѿ����ã�����ǰ����һ��δȷ�ϵ��ж�
#define IRQ_REPLAY		0x00000800	/* IRQ has been replayed but not acked yet */
//����IRQ�Զ���������
#define IRQ_AUTODETECT		0x00001000	/* IRQ is being autodetected */
//����IRQ�Զ���������
#define IRQ_WAITING		0x00002000	/* IRQ not yet seen - for autodetection */
//����Alpha��PowerPCϵͳ���������ֵ�ƽ�����ͱ��ش�����IRQ
#define IRQ_LEVEL		0x00004000	/* IRQ level triggered */
//Ϊ��ȷ���������жϴ����ڼ���жϣ���ҪIRQ_MASKED��־
#define IRQ_MASKED		0x00008000	/* IRQ masked - shouldn't be seen again */
//��ĳ��IRQֻ�ܷ�����һ��CPU��ʱ��������IRQ_PER_CPU��־λ��
//(��SMPϵͳ�У��ñ�־ʹ�������ڷ�ֹ�������ʵı������Ʊ�ö���)
#define IRQ_PER_CPU		0x00010000	/* IRQ is per CPU */
#define IRQ_NOPROBE		0x00020000	/* IRQ is not valid for probing */
//�����ǰIRQ�����ɶ���豸��������ר����ĳһ�豸��������IRQ_NOREQUEST��־
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
//�����ͳ������һ��IRQ�������ľ����������������ں˵���ϵ�����޹ز��֡�
//���ṩ�ĺ������ڸı�IRQ��״̬����Ҳ�����ǻ���������flag��ԭ��
//�ýṹ��Ҫ�����ں��г��ֵĸ���IRQʵ�ֵ��������ԡ�
//�����һ���ýṹ���ض�ʵ����ͨ��ֻ�������п��ܷ�����һ���Ӽ�
struct irq_chip {
	//���ڱ�ʶӲ����������
	//��IA-32ϵͳ�Ͽ��ܵ�ֵ��"XTPIC"��"IO-APIC"����AMD64ϵͳ�ϴ���������Ҳ��ʹ�ú��ߡ�
	//������ϵͳ���и��ָ�����ֵ��
	const char	*name;
	//���ڵ�һ�γ�ʼ��һ��IRQ���ڴ��������£���ʼ���������������ø�IRQ
	//�����startup����ʵ���Ͼ��ǽ�����ת��enable��
	unsigned int	(*startup)(unsigned int irq);
	//��ȫ�ر�һ���ж�Դ��
	//�����֧�ָ����ԣ���ô�������ʵ������disable�ı���
	void		(*shutdown)(unsigned int irq);
	//����һ��IRQ.
	//���仰˵����ִ��IRQ�ɽ���״̬������״̬��ת����
	//Ϊ�ˣ�������I/O�ڴ��I/O�˿���Ӳ����ص�λ��д���ض���Ӳ������ֵ
	void		(*enable)(unsigned int irq);
	//��enable���Ӧ�����ڽ���IRQ��
	void		(*disable)(unsigned int irq);
	//ack���жϿ�������Ӳ��������ء���ĳЩģ���У�IRQ����ĵ���
	//(�Լ��ڴ������Ķ�Ӧ�ж�)������ʾȷ�ϣ�������������ܽ��д���
	//���оƬ��û��������Ҫ�󣬸�ָ�����ָ��һ���պ�������NULLָ�롣
	void		(*ack)(unsigned int irq);
	void		(*mask)(unsigned int irq);
	//ȷ��һ���жϣ����ڽ��������θ��ж��
	void		(*mask_ack)(unsigned int irq);
	void		(*unmask)(unsigned int irq);
	//�ִ����жϿ���������Ҫ�ں˽���̫��ĵ������ƣ��������������Թ�����������
	//�ڴ����ж�ʱ��Ҫһ����Ӳ���Ļص�����eoi�ṩ��eoi��ʾend of interrupt�����жϽ���
	void		(*eoi)(unsigned int irq);

	//����жϴ����ڵ�����εĽ�����
	//���һ���ж����жϴ����ڼ䱻���ã���ô�ú��������������ô����ж�
	void		(*end)(unsigned int irq);
	//�ڶദ����ϵͳ�У�����ʹ��set_affinityָ��CPU�������ض���IRQ.
	//��ʹ�ÿ��Խ�IRQ�����ĳЩCPU(ͨ����SMPϵͳ�ϵ�IRQ��ƽ�ַ��������д�������)��
	//�÷����ڵ�������ϵͳ��û�ã���������ΪNULLָ��
	void		(*set_affinity)(unsigned int irq, cpumask_t dest);
	int		(*retrigger)(unsigned int irq);
	//����IRQ�ĵ������͡�
	//�÷�����Ҫʹ����ARM��PowerPC��SuperH�����ϣ�����ϵͳ����Ҫ�÷�������������ΪNULL
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
	const char	*typename;//Ϊ�˼����Զ�ʹ��
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
//����ÿ��IRQ�ж��ߣ�Linux����һ��irq_desc_t���ݽṹ�����������ǰ�������IRQ������
struct irq_desc
{
	//������ISR��handle_irq�ṩ��
	//ÿ�������ж�ʱ���ض�����ϵ�ṹ�Ĵ��붼�����handle_irq��
	//�ú�������ʹ��chip���ṩ���ض��ڿ������ķ��������д����ж��������һЩ�ײ������
	irq_flow_handler_t	handle_irq;
	//���������оƬ��ز�������װ��chip�С�
	struct irq_chip		*chip;
	struct msi_desc		*msi_desc;
	//����ָ���������ݣ������ݿ������ض���IRQ�������ġ�
	void			*handler_data;
	//ָ�������chip��ص���������
	void			*chip_data;
	//�ṩ��һ������������Ҫ���жϷ���ʱִ�С�
	//���ж�֪ͨ���豸�������򣬿��Խ���֮��صĴ�������������ڴ˴�
	struct irqaction	*action;	/* IRQ action list */
	//������IRQ�ĵ�ǰ״̬��
	//����status��ǰֵ���ں˺����׻���ĳ��IRQ��״̬���������˽�ײ�ʵ�ֵ�Ӳ��������ԡ�
	//��Ȼֻ���ö�Ӧ�ı�־λ�ǲ������Ԥ��Ч���ģ������뽫��״̬֪ͨ�ײ�Ӳ����
	//������ñ�־ֻ��ͨ���ض��ڿ������ĺ������ã���Щ����ͬʱ������������Ϣͬ�����ײ�Ӳ����
	//�ںܶ�����£������ʹ�û�����Դ��룬��ͨ��out�������ض���ַд���ض���ֵ��
	unsigned int		status;		/* IRQ status */

	//����ȷ��IRQ��·�����õĻ��ǽ��õġ���ֵ��ʾ���ã���0��ʾ����
	//Ϊʲô����ֵ��ʾ����IRQ��� ��Ϊ��ʹ���ں��ܹ��������úͽ��õ�IRQ��·��
	//�Լ��ظ�����ͬһ�жϵ����Ρ����ֵ�൱��һ�����������ں����ಿ�ֵĴ���
	//ÿ�ν���ĳ���жϣ��򽫶�Ӧ�ļ�������1��ÿ���жϱ��ٴ����ã��򽫼�������1��
	//��depth��0ʱ��Ӳ�������ٴ�ʹ�ö�Ӧ��IRQ�����ַ����ܹ�֧�ֶ�Ƕ�׽����жϵ���ȷ����
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
	//ָ���˵����㴦���������ƣ�����ʾ��/proc/interrupts�С�
	//�Ա��ش����жϣ�ͨ������"edge"���Ե�ƽ�����жϣ�ͨ����"level"
	const char		*name;
} ____cacheline_internodealigned_in_smp;

extern struct irq_desc irq_desc[NR_IRQS];

/*
 * Migration helpers for obsolete names, they will go away:
 */
#define hw_interrupt_type	irq_chip //Ϊ�˼���IRQ��ϵͳ��ǰһ�汾
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
//Ϊĳ��������IRQ������õ����������
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
//Ϊĳ��������IRQ������õ���������򣬴��������봦������жϡ�
//�������irq_desc[irq]->status�еı�־λIRQ_NOREQUEST��IRQ_NOPROBE
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
