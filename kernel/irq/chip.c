/*
 * linux/kernel/irq/chip.c
 *
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code, for irq-chip
 * based architectures.
 *
 * Detailed information is available in Documentation/DocBook/genericirq
 */

#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include "internals.h"

/**
 *	dynamic_irq_init - initialize a dynamically allocated irq
 *	@irq:	irq number to initialize
 */
void dynamic_irq_init(unsigned int irq)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR "Trying to initialize invalid IRQ%d\n", irq);
		WARN_ON(1);
		return;
	}

	/* Ensure we don't have left over values from a previous use of this irq */
	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock, flags);
	desc->status = IRQ_DISABLED;
	desc->chip = &no_irq_chip;
	desc->handle_irq = handle_bad_irq;
	desc->depth = 1;
	desc->msi_desc = NULL;
	desc->handler_data = NULL;
	desc->chip_data = NULL;
	desc->action = NULL;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
#ifdef CONFIG_SMP
	desc->affinity = CPU_MASK_ALL;
#endif
	spin_unlock_irqrestore(&desc->lock, flags);
}

/**
 *	dynamic_irq_cleanup - cleanup a dynamically allocated irq
 *	@irq:	irq number to initialize
 */
void dynamic_irq_cleanup(unsigned int irq)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR "Trying to cleanup invalid IRQ%d\n", irq);
		WARN_ON(1);
		return;
	}

	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock, flags);
	if (desc->action) {
		spin_unlock_irqrestore(&desc->lock, flags);
		printk(KERN_ERR "Destroying IRQ%d without calling free_irq\n",
			irq);
		WARN_ON(1);
		return;
	}
	desc->msi_desc = NULL;
	desc->handler_data = NULL;
	desc->chip_data = NULL;
	desc->handle_irq = handle_bad_irq;
	desc->chip = &no_irq_chip;
	spin_unlock_irqrestore(&desc->lock, flags);
}


/**
 *	set_irq_chip - set the irq chip for an irq
 *	@irq:	irq number
 *	@chip:	pointer to irq chip description structure
 */
//½«Ò»¸öIRQÐ¾Æ¬ÒÑirq_chipÊµÀýµÄÐÎÊ½¹ØÁªµ½Ä³¸öÌØ¶¨µÄÖÐ¶Ï¡£
//Èç¹ûÃ»ÓÐÌá¹©ÌØ¶¨ÓÚÐ¾Æ¬µÄÊµÏÖ£¬¸Ãº¯Êý»¹½«ÉèÖÃÄ¬ÈÏµÄ´¦Àí³ÌÐò¡£
//Èç¹ûchipÖ¸ÕëÎªNULL£¬½«Ê¹ÓÃÍ¨ÓÃµÄ"ÎÞ¿ØÖÆÆ÷"irq_chipÊµÀýno_irq_chip£¬¸ÃÊµÏÖÖ»Ìá¹©ÁË¿Õ²Ù×÷
int set_irq_chip(unsigned int irq, struct irq_chip *chip)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR "Trying to install chip for IRQ%d\n", irq);
		WARN_ON(1);
		return -EINVAL;
	}

	if (!chip)
		chip = &no_irq_chip;

	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock, flags);
	irq_chip_set_defaults(chip);
	desc->chip = chip;
	spin_unlock_irqrestore(&desc->lock, flags);

	return 0;
}
EXPORT_SYMBOL(set_irq_chip);

/**
 *	set_irq_type - set the irq type for an irq
 *	@irq:	irq number
 *	@type:	interrupt type - see include/linux/interrupt.h
 */
int set_irq_type(unsigned int irq, unsigned int type)
{
	struct irq_desc *desc;
	unsigned long flags;
	int ret = -ENXIO;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR "Trying to set irq type for IRQ%d\n", irq);
		return -ENODEV;
	}

	desc = irq_desc + irq;
	if (desc->chip->set_type) {
		spin_lock_irqsave(&desc->lock, flags);
		ret = desc->chip->set_type(irq, type);
		spin_unlock_irqrestore(&desc->lock, flags);
	}
	return ret;
}
EXPORT_SYMBOL(set_irq_type);

/**
 *	set_irq_data - set irq type data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to interrupt specific data
 *
 *	Set the hardware irq controller data for an irq
 */
int set_irq_data(unsigned int irq, void *data)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR
		       "Trying to install controller data for IRQ%d\n", irq);
		return -EINVAL;
	}

	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock, flags);
	desc->handler_data = data;
	spin_unlock_irqrestore(&desc->lock, flags);
	return 0;
}
EXPORT_SYMBOL(set_irq_data);

/**
 *	set_irq_data - set irq type data for an irq
 *	@irq:	Interrupt number
 *	@entry:	Pointer to MSI descriptor data
 *
 *	Set the hardware irq controller data for an irq
 */
int set_irq_msi(unsigned int irq, struct msi_desc *entry)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR
		       "Trying to install msi data for IRQ%d\n", irq);
		return -EINVAL;
	}
	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock, flags);
	desc->msi_desc = entry;
	if (entry)
		entry->irq = irq;
	spin_unlock_irqrestore(&desc->lock, flags);
	return 0;
}

/**
 *	set_irq_chip_data - set irq chip data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to chip specific data
 *
 *	Set the hardware irq chip data for an irq
 */
int set_irq_chip_data(unsigned int irq, void *data)
{
	struct irq_desc *desc = irq_desc + irq;
	unsigned long flags;

	if (irq >= NR_IRQS || !desc->chip) {
		printk(KERN_ERR "BUG: bad set_irq_chip_data(IRQ#%d)\n", irq);
		return -EINVAL;
	}

	spin_lock_irqsave(&desc->lock, flags);
	desc->chip_data = data;
	spin_unlock_irqrestore(&desc->lock, flags);

	return 0;
}
EXPORT_SYMBOL(set_irq_chip_data);

/*
 * default enable function
 */
static void default_enable(unsigned int irq)
{
	struct irq_desc *desc = irq_desc + irq;

	desc->chip->unmask(irq);
	desc->status &= ~IRQ_MASKED;
}

/*
 * default disable function
 */
static void default_disable(unsigned int irq)
{
}

/*
 * default startup function
 */
static unsigned int default_startup(unsigned int irq)
{
	irq_desc[irq].chip->enable(irq);

	return 0;
}

/*
 * Fixup enable/disable function pointers
 */
void irq_chip_set_defaults(struct irq_chip *chip)
{
	if (!chip->enable)
		chip->enable = default_enable;
	if (!chip->disable)
		chip->disable = default_disable;
	if (!chip->startup)
		chip->startup = default_startup;
	if (!chip->shutdown)
		chip->shutdown = chip->disable;
	if (!chip->name)
		chip->name = chip->typename;
	if (!chip->end)
		chip->end = dummy_irq_chip.end;
}

static inline void mask_ack_irq(struct irq_desc *desc, int irq)
{
	if (desc->chip->mask_ack)
		desc->chip->mask_ack(irq);
	else 
	{
		desc->chip->mask(irq);
		desc->chip->ack(irq);
	}
}

/**
 *	handle_simple_irq - Simple and software-decoded IRQs.
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Simple interrupts are either sent from a demultiplexing interrupt
 *	handler or come from hardware, where no interrupt hardware control
 *	is necessary.
 *
 *	Note: The caller is expected to handle the ack, clear, mask and
 *	unmask issues if necessary.
 */
//·Ç³£¼òµ¥£¬¸ù±¾²»ÐèÒªµçÁ÷¿ØÖÆµÄÖÐ¶ÏÓÉhandle_simple_irq¹ÜÀí¡£
//Èç¹ûµ÷ÓÃÕßÏëÒª×ÔÐÐ´¦ÀíµçÁ÷£¬Ò²¿ÉÒÔÊ¹ÓÃ¸Ãº¯Êý¡£
void fastcall handle_simple_irq(unsigned int irq, struct irq_desc *desc)
{
	struct irqaction *action;
	irqreturn_t action_ret;
	const unsigned int cpu = smp_processor_id();

	spin_lock(&desc->lock);

	if (unlikely(desc->status & IRQ_INPROGRESS))
		goto out_unlock;
	desc->status &= ~(IRQ_REPLAY | IRQ_WAITING);
	kstat_cpu(cpu).irqs[irq]++;

	action = desc->action;
	if (unlikely(!action || (desc->status & IRQ_DISABLED)))
		goto out_unlock;

	desc->status |= IRQ_INPROGRESS;
	spin_unlock(&desc->lock);

	action_ret = handle_IRQ_event(irq, action);
	if (!noirqdebug)
		note_interrupt(irq, desc, action_ret);

	spin_lock(&desc->lock);
	desc->status &= ~IRQ_INPROGRESS;
out_unlock:
	spin_unlock(&desc->lock);
}

/**
 *	handle_level_irq - Level type irq handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Level type interrupts are active as long as the hardware line has
 *	the active level. This may require to mask the interrupt and unmask
 *	it after the associated handler has acknowledged the device, so the
 *	interrupt line is back to inactive.
 */
//Ä¬ÈÏµÄµçÆ½´¥·¢µçÁ÷´¦Àí³ÌÐò¡£
//×¢Òâ£¬µçÆ½´¥·¢ÖÐ¶ÏÔÚ´¦ÀíÊ±±ØÐëÆÁ±Î£¬Òò´ËÐèÒªÍê³ÉµÄµÚÒ»¼þÊÂ¾ÍÊÇµ÷ÓÃmask_ack_irq¡£
//ÔÚ¶à´¦ÀíÆ÷ÏµÍ³ÉÏ£¬¿ÉÄÜ·¢Éú¾ºÌ¬Ìõ¼þ£¬¾¡¹ÜIRQÒÑ¾­ÔÚÁíÒ»¸öCPUÉÏ´¦Àí£¬
//µ«ÈÔÈ»ÔÚµ±Ç°CPUÉÏµ÷ÓÃÁËhandle_level_irq¡£Õâ¿ÉÒÔÍ¨¹ý¼ì²éIRQ_INPROGRESS±êÖ¾À´ÅÐ¶Ï£¬
//ÕâÖÖÇé¿öÏÂ£¬IRQÒÑ¾­ÔÚÁíÒ»¸öCPUÉÏ´¦Àí£¬Òò¶øÔÚµ±Ç°CPUÉÏ¿ÉÒÔÁ¢¼´·ÅÆú´¦Àí¡£
void fastcall handle_level_irq(unsigned int irq, struct irq_desc *desc)
{
	unsigned int cpu = smp_processor_id();
	struct irqaction *action;
	irqreturn_t action_ret;

	spin_lock(&desc->lock);
	mask_ack_irq(desc, irq);

	if (unlikely(desc->status & IRQ_INPROGRESS))
		goto out_unlock;
	desc->status &= ~(IRQ_REPLAY | IRQ_WAITING);
	kstat_cpu(cpu).irqs[irq]++;

	/*
	 * If its disabled or no action available
	 * keep it masked and get out of here
	 */
	action = desc->action;
	//Ã»ÓÐ¶Ô¸ÃIRQ×¢²á´¦Àí³ÌÐò»òÉèÖÃÁËIRQ_DISABLED£¬ÔòÁ¢¼´·ÅÆú´¦Àí¡£
	//¾¡¹Ü±»½ûÓÃ£¬ÓÐÎÊÌâµÄÓ²¼þÈÔÈ»¿ÉÄÜ·¢³öIRQ£¬µ«¿ÉÒÔºöÂÔ¡£
	if (unlikely(!action || (desc->status & IRQ_DISABLED)))
		goto out_unlock;

	desc->status |= IRQ_INPROGRESS;
	spin_unlock(&desc->lock);

	action_ret = handle_IRQ_event(irq, action);
	if (!noirqdebug)
		note_interrupt(irq, desc, action_ret);

	spin_lock(&desc->lock);
	desc->status &= ~IRQ_INPROGRESS;
	//½â³ý¶ÔIRQµÄÆÁ±Î¡£µ«ÄÚºËÐèÒª¿¼ÂÇµ½ISR¿ÉÄÜ½ûÓÃÖÐ¶ÏµÄÇé¿ö£¬
	//ÔÚÕâÖÖÇé¿öÏÂ£¬ISRÈÔÈ»±£³ÖÆÁ±Î×´Ì¬¡£·ñÔò£¬Ê¹ÓÃÌØ¶¨ÓÚÐ¾Æ¬µÄº¯Êýchip->umask½â³ýÆÁ±Î
	if (!(desc->status & IRQ_DISABLED) && desc->chip->unmask)
		desc->chip->unmask(irq);
out_unlock:
	spin_unlock(&desc->lock);
}

/**
 *	handle_fasteoi_irq - irq handler for transparent controllers
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Only a single callback will be issued to the chip: an ->eoi()
 *	call when the interrupt has been serviced. This enables support
 *	for modern forms of interrupt handlers, which handle the flow
 *	details in hardware, transparently.
 */
//ÏÖ´úIRQÓ²¼þÖ»ÐèÒª¼«ÉÙµÄµçÁ÷´¦Àí¹¤×÷¡£
//Ö»ÐèÔÚIRQ´¦Àí½áÊøÖ®ºóµ÷ÓÃÒ»¸öÐ¾Æ¬Ïà¹ØµÄº¯Êýchip->eoi¡£
//´ËÀàÐÍµÄÄ¬ÈÏ´¦Àí³ÌÐòÊÇhandle_fasteoi_irq
//Ëü»ù±¾ÉÏµÈÍ¬ÓÚhandle_level_irq£¬³ýÁËÖ»ÐèÔÚ×îºóÓë¿ØÖÆÆ÷Ð¾Æ¬½»»¥¡£
void fastcall handle_fasteoi_irq(unsigned int irq, struct irq_desc *desc)
{
	unsigned int cpu = smp_processor_id();
	struct irqaction *action;
	irqreturn_t action_ret;

	spin_lock(&desc->lock);

	if (unlikely(desc->status & IRQ_INPROGRESS))
		goto out;

	desc->status &= ~(IRQ_REPLAY | IRQ_WAITING);
	kstat_cpu(cpu).irqs[irq]++;

	/*
	 * If its disabled or no action available
	 * then mask it and get out of here:
	 */
	action = desc->action;
	if (unlikely(!action || (desc->status & IRQ_DISABLED)))
	{
		desc->status |= IRQ_PENDING;
		if (desc->chip->mask)
			desc->chip->mask(irq);
		goto out;
	}

	desc->status |= IRQ_INPROGRESS;
	desc->status &= ~IRQ_PENDING;
	spin_unlock(&desc->lock);

	action_ret = handle_IRQ_event(irq, action);
	if (!noirqdebug)
		note_interrupt(irq, desc, action_ret);

	spin_lock(&desc->lock);
	desc->status &= ~IRQ_INPROGRESS;
out:
	desc->chip->eoi(irq);

	spin_unlock(&desc->lock);
}

/**
 *	handle_edge_irq - edge type IRQ handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Interrupt occures on the falling and/or rising edge of a hardware
 *	signal. The occurence is latched into the irq controller hardware
 *	and must be acked in order to be reenabled. After the ack another
 *	interrupt can happen on the same source even before the first one
 *	is handled by the assosiacted event handler. If this happens it
 *	might be necessary to disable (mask) the interrupt depending on the
 *	controller hardware. This requires to reenable the interrupt inside
 *	of the loop which handles the interrupts which have arrived while
 *	the handler was running. If all pending interrupts are handled, the
 *	loop is left.
 */
//Ä¬ÈÏµÄ±ßÑØ´¥·¢µçÁ÷´¦Àí³ÌÐò¡£
//ÔÚ´¦Àí±ßÑØ´¥·¢µÄIRQÊ±ÎÞÐèÆÁ±Î£¬ÕâÓëµçÆ½´¥·¢IRQÊÇÏà·´µÄ¡£
//Õâ¶ÔSMPÏµÍ³ÓÐÒ»¸öÖØÒªµÄº¬Òå: µ±ÔÚÒ»¸öCPUÉÏ´¦ÀíÒ»¸öIRQÊ±£¬
//ÁíÒ»¸öÍ¬Ñù±àºÅµÄIRQ¿ÉÒÔ³öÏÖÔÚÁíÒ»¸öCPUÉÏ£¬³ÆÎªµÚ¶þ¸öCPU¡£
//ÕâÒâÎ¶×Å£¬µ±µçÁ÷´¦Àí³ÌÐòÔÚÓÉµÚÒ»¸öIRQ´¥·¢µÄCPUÉÏÔËÐÐÊ±£¬»¹¿ÉÄÜ±»ÔÙ´Îµ÷ÓÃ¡£
//µ«ÎªÊ²Ã´Ó¦¸ÃÓÉÁ½¸öCPUÍ¬Ê±ÔËÐÐÍ¬Ò»¸öIRQ´¦Àí³ÌÐòÄØå ÄÚºËÏëÒª±ÜÃâÕâÖÖÇé¿ö
//´¦Àí³ÌÐòÖ»Ó¦¸ÃÔÚÒ»¸öCPUÉÏÔËÐÐ¡£handle_edge_irqµÄ¿ªÊ¼²¿·Ö±ØÐë´¦ÀíÕâÖÖÇé¿ö¡£
//Èç¹ûÉèÖÃÁËIRQ_INPROGRESS±êÖ¾£¬Ôò¸ÃIRQÔÚÁíÒ»¸öCPUÉÏÒÑ¾­´¦ÓÚ´¦Àí¹ý³ÌÖÐ¡£
//Í¨¹ýÉèÖÃIRQ_PENDING±êÖ¾£¬ÄÚºËÄÜ¹»¼ÇÂ¼»¹ÓÐÁíÒ»¸öIRQÐèÒªÔÚÉÔºó´¦Àí¡£
//ÔÚÆÁ±Î¸ÃIRQ²¢Í¨¹ýmask_ack_irqÏò¿ØÖÆÆ÷·¢ËÍÒ»¸öÈ·ÈÏºó£¬´¦Àí¹ý³Ì¿ÉÒÔ·ÅÆú¡£
//Òò¶øµÚ¶þ¸öCPU¿ÉÒÔ»Ö¸´Õý³£µÄ¹¤×÷£¬¶øµÚÒ»¸öCPU½«ÔÚÉÔºó´¦Àí¸ÃIRQ.
//×¢Òâ£¬Èç¹ûIRQ±»½ûÓÃ£¬»òÃ»ÓÐ¿ÉÓÃµÄISR´¦Àí³ÌÐò£¬¶¼»á·ÅÆú´¦Àí¡£
//(ÓÐÈ±ÏÝµÄÓ²¼þ¿ÉÄÜÔÚIRQ½ûÓÃµÄÇé¿öÏÂÈÔÈ»Éú³ÉIRQ£¬ÄÚºËÐèÒª¿¼ÂÇµ½ÕâÖÖÇé¿ö)
void fastcall handle_edge_irq(unsigned int irq, struct irq_desc *desc)
{
	const unsigned int cpu = smp_processor_id();

	spin_lock(&desc->lock);

	desc->status &= ~(IRQ_REPLAY | IRQ_WAITING);

	/*
	 * If we're currently running this IRQ, or its disabled,
	 * we shouldn't process the IRQ. Mark it pending, handle
	 * the necessary masking and go out
	 */
	//Ã»ÓÐ´¦Àí³ÌÐò£¬IRQÔÚ´¦ÀíÖÐ»òIRQ½ûÓÃ
	if (unlikely((desc->status & (IRQ_INPROGRESS | IRQ_DISABLED)) || !desc->action)) 
	{
		desc->status |= (IRQ_PENDING | IRQ_MASKED);
		mask_ack_irq(desc, irq);
		goto out_unlock;
	}

	kstat_cpu(cpu).irqs[irq]++;

	/* Start handling the irq */
	desc->chip->ack(irq);

	/* Mark the IRQ currently in progress.*/
	//ÄÚºËÉèÖÃIRQ_INPROGRESS±êÖ¾¡£
	//Õâ±íÊ¾IRQÕýÔÚ´¦Àí¹ý³ÌÖÐ£¬¿ÉÓÃÓÚ±ÜÃâÍ¬Ò»´¦Àí³ÌÐòÔÚ¶à¸öCPUÉÏÖ´ÐÐ
	desc->status |= IRQ_INPROGRESS;

	do 
	{
		struct irqaction *action = desc->action;
		irqreturn_t action_ret;

		if (unlikely(!action))
		{
			desc->chip->mask(irq);
			goto out_unlock;
		}

		/*
		 * When another irq arrived while we were handling 
		 * one, we could have masked the irq.
		 * Renable it, if it was not disabled in meantime.
		 * Èç¹ûÔÚ´¦ÀíirqÊ±ÓÐÁíÒ»¸öirqµ½´ï£¬ÄÇÃ´µ±Ê±¿ÉÄÜÆÁ±ÎÁË¸Ãirq¡£
		 * ½â³ý¶ÔirqµÄÆÁ±Î£¬Èç¹ûËüÔÚ´ËÆÚ¼äÃ»ÓÐ±»½ûÓÃµÄ»°¡£
		 */
		if (unlikely((desc->status &(IRQ_PENDING | IRQ_MASKED | IRQ_DISABLED)) 
				== (IRQ_PENDING | IRQ_MASKED))) 
		{
			desc->chip->unmask(irq);
			desc->status &= ~IRQ_MASKED;
		}

		desc->status &= ~IRQ_PENDING;
		spin_unlock(&desc->lock);
		//Í¨¹ýµ÷ÓÃhandle_IRQ_event¼¤»î¸ß²ãISR´¦Àí³ÌÐò
		action_ret = handle_IRQ_event(irq, action);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		spin_lock(&desc->lock);

	}//Ö»ÒªIRQ_PENDINGÈÎÈ»ÖÃÎ»£¬¶øÇÒIRQÃ»ÓÐ½ûÓÃ£¬¾ÍÒ»Ö±µü´úÏÂÈ¥
	while ((desc->status & (IRQ_PENDING | IRQ_DISABLED)) == IRQ_PENDING);

	desc->status &= ~IRQ_INPROGRESS;
out_unlock:
	spin_unlock(&desc->lock);
}

/**
 *	handle_percpu_IRQ - Per CPU local irq handler
 *	@irq:	the interrupt number
 *	@desc:	the interrupt description structure for this irq
 *
 *	Per CPU interrupts on SMP machines without locking requirements
 */
//¸÷CPU IRQ£¬¼´IRQÖ»ÄÜ·¢ËÍµ½¶à´¦ÀíÆ÷ÏµÍ³µÄÒ»¸öÌØ¶¨µÄCPU£¬ÓÉhandle_percpu_irq´¦Àí¡£
//¸Ãº¯ÊýÔÚ½ÓÊÕÖ®ºóÈ·ÈÏIRQ£¬ÔÚ´¦ÀíÖ®ºóµ÷ÓÃeoiÀý³Ì¡£
//ÆäÊµÏÖ·Ç³£¼òµ¥£¬ÒòÎª²»ÐèÒªËø£¬¸ù¾Ý¶¨Òå´úÂëÖ»ÄÜÔÚÒ»¸öCPUÉÏÔËÐÐ¡£
void fastcall handle_percpu_irq(unsigned int irq, struct irq_desc *desc)
{
	irqreturn_t action_ret;

	kstat_this_cpu.irqs[irq]++;

	if (desc->chip->ack)
		desc->chip->ack(irq);

	action_ret = handle_IRQ_event(irq, desc->action);
	if (!noirqdebug)
		note_interrupt(irq, desc, action_ret);

	if (desc->chip->eoi)
		desc->chip->eoi(irq);
}

void
__set_irq_handler(unsigned int irq, irq_flow_handler_t handle, int is_chained,
		  const char *name)
{
	struct irq_desc *desc;
	unsigned long flags;

	if (irq >= NR_IRQS) {
		printk(KERN_ERR
		       "Trying to install type control for IRQ%d\n", irq);
		return;
	}

	desc = irq_desc + irq;

	if (!handle)
		handle = handle_bad_irq;
	else if (desc->chip == &no_irq_chip) {
		printk(KERN_WARNING "Trying to install %sinterrupt handler "
		       "for IRQ%d\n", is_chained ? "chained " : "", irq);
		/*
		 * Some ARM implementations install a handler for really dumb
		 * interrupt hardware without setting an irq_chip. This worked
		 * with the ARM no_irq_chip but the check in setup_irq would
		 * prevent us to setup the interrupt at all. Switch it to
		 * dummy_irq_chip for easy transition.
		 */
		desc->chip = &dummy_irq_chip;
	}

	spin_lock_irqsave(&desc->lock, flags);

	/* Uninstall? */
	if (handle == handle_bad_irq) {
		if (desc->chip != &no_irq_chip)
			mask_ack_irq(desc, irq);
		desc->status |= IRQ_DISABLED;
		desc->depth = 1;
	}
	desc->handle_irq = handle;
	desc->name = name;

	if (handle != handle_bad_irq && is_chained) {
		desc->status &= ~IRQ_DISABLED;
		desc->status |= IRQ_NOREQUEST | IRQ_NOPROBE;
		desc->depth = 0;
		desc->chip->unmask(irq);
	}
	spin_unlock_irqrestore(&desc->lock, flags);
}

void
set_irq_chip_and_handler(unsigned int irq, struct irq_chip *chip,
			 irq_flow_handler_t handle)
{
	set_irq_chip(irq, chip);
	__set_irq_handler(irq, handle, 0, NULL);
}

void
set_irq_chip_and_handler_name(unsigned int irq, struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name)
{
	set_irq_chip(irq, chip);
	__set_irq_handler(irq, handle, 0, name);
}
