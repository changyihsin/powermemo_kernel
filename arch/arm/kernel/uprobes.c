/*
 * User-space Probes (UProbes)
 * arch/i386/kernel/uprobes.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2006.
 *
 * 2006-Mar Created by Prasanna S Panchamukhi <prasanna@xxxxxxxxxx>
 * User-space probes initial implementation.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/preempt.h>
#include <asm/cacheflush.h>
#include <asm/kdebug.h>
#include <asm/uaccess.h>
#include <asm/traps.h>


static struct uprobe_ctlblk uprobe_ctlblk;


#define flush_insns(addr, cnt)				\
	flush_icache_range((unsigned long)(addr),	\
			   (unsigned long)(addr) +	\
			   sizeof(kprobe_opcode_t) * (cnt))

#define flush_user_insns(vma, start, end)				\
		flush_cache_user_range(start, end)

extern struct uprobe_module *get_module_by_inode(struct inode *inode);
extern void *xol_alloc_area(void);
extern void xol_free_area(void *xol_area);
extern unsigned long xol_get_insn_slot(void *xol_area);
extern void xol_free_insn_slot(unsigned long slot_addr, void *xol_area);
extern void HELLO();
extern void HELLO2();

/*
 * This routines get the pte of the page containing the specified address.
 */
static pte_t  __kprobes *get_uprobe_pte(unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte = NULL;

	pgd = pgd_offset(current->mm, address);	
	pud = pud_alloc(current->mm, pgd, address);
	if (!pud)
		return pte;
	pmd = pmd_alloc(current->mm, pud, address);	
	if (!pmd)
		return pte;
	pte = pte_alloc_map(current->mm, pmd, address);	
	return pte;
}
/*
 * This routine checks for stack free space below the stack pointer
 * and then copies the instructions at that location so that the
 * processor can single step out-of-line. If there is not enough stack
 * space or if copy_to_user fails or if the vma is invalid, it returns
 * error.
 */
static int __kprobes copy_insn_to_xol(struct uprobe *uprobe,
			struct pt_regs *regs, unsigned long vaddr, unsigned long flags)
{
	unsigned long *source1;
	unsigned long *source2;
	kprobe_opcode_t *dest_addr;

	source1 = (unsigned long *)&uprobe->kp.ainsn.insn[0];
	source2 = (unsigned long *)&uprobe->kp.ainsn.insn[1];
	dest_addr = (kprobe_opcode_t *)vaddr;
	generic_ptrace_pokedata(current, dest_addr, *source1);
	dest_addr = (kprobe_opcode_t *)(vaddr + 4);
	generic_ptrace_pokedata(current, dest_addr, *source2);
	return 0;
}

/**
 *  This routine check for space in the current process's stack
 *  address space. If enough address space is found, copy the original
 *  instruction on that page for single stepping out-of-line.
 */
static int __kprobes copy_insn_on_new_page(struct uprobe *uprobe ,
			struct pt_regs *regs, struct vm_area_struct *vma)
{
	unsigned long addr, stack_addr = regs->ARM_sp;
	int size = MAX_INSN_SIZE * sizeof(kprobe_opcode_t);

	if (vma->vm_flags & VM_GROWSDOWN) {
		if (((stack_addr - sizeof(long long))) <
						(vma->vm_start + size))
			return -ENOMEM;
		addr = vma->vm_start;
	} else if (vma->vm_flags & VM_GROWSUP) {
		if ((vma->vm_end - size) < (stack_addr + sizeof(long long)))
			return -ENOMEM;
		addr = vma->vm_end - size;
	} else
		return -EFAULT;

	vma->vm_flags |= VM_LOCKED;

	if (__copy_to_user_inatomic((unsigned long *)addr,
				(unsigned long *)uprobe->kp.ainsn.insn, size))
		return -EFAULT;

	regs->ARM_pc = addr;

	return 0;
}

/**
 * This routine expands the stack beyond the present process address
 * space and copies the instruction to that location, so that
 * processor can single step out-of-line.
 */
static int __kprobes copy_insn_onexpstack(struct uprobe *uprobe,
			struct pt_regs *regs, struct vm_area_struct *vma)
{
	unsigned long addr, vm_addr;
	int size = MAX_INSN_SIZE * sizeof(kprobe_opcode_t);
	struct vm_area_struct *new_vma;
	struct mm_struct *mm = current->mm;


	 if (!down_read_trylock(&current->mm->mmap_sem))
		 return -ENOMEM;

	if (vma->vm_flags & VM_GROWSDOWN)
		vm_addr = vma->vm_start - size;
	else if (vma->vm_flags & VM_GROWSUP)
		vm_addr = vma->vm_end + size;
	else {
		up_read(&current->mm->mmap_sem);
		return -EFAULT;
	}

	new_vma = find_extend_vma(mm, vm_addr);
	if (!new_vma) {
		up_read(&current->mm->mmap_sem);
		return -ENOMEM;
	}

	if (new_vma->vm_flags & VM_GROWSDOWN)
		addr = new_vma->vm_start;
	else
		addr = new_vma->vm_end - size;

	new_vma->vm_flags |= VM_LOCKED;
	up_read(&current->mm->mmap_sem);

	if (__copy_to_user_inatomic((unsigned long *)addr,
				(unsigned long *)uprobe->kp.ainsn.insn, size))
		return -EFAULT;

	regs->ARM_pc = addr;

	return  0;
}

/**
 * This routine checks for stack free space below the stack pointer
 * and then copies the instructions at that location so that the
 * processor can single step out-of-line. If there is not enough stack
 * space or if copy_to_user fails or if the vma is invalid, it returns
 * error.
 */
static int __kprobes copy_insn_onstack(struct uprobe *uprobe,
			struct pt_regs *regs, unsigned long flags)
{
	unsigned long page_addr, stack_addr = regs->ARM_sp;
	int  size = MAX_INSN_SIZE * sizeof(kprobe_opcode_t);
	unsigned long *source = (unsigned long *)uprobe->kp.ainsn.insn;

	if (flags & VM_GROWSDOWN) {
		page_addr = stack_addr & PAGE_MASK;

		if (((stack_addr - sizeof(long long))) < (page_addr + size))
			return -ENOMEM;

		if (__copy_to_user_inatomic((unsigned long *)page_addr,
								source, size))
			return -EFAULT;

		regs->ARM_pc = page_addr;
	} else if (flags & VM_GROWSUP) {
		page_addr = stack_addr & PAGE_MASK;

		if (page_addr == stack_addr)
			return -ENOMEM;
		else
			page_addr += PAGE_SIZE;

		if ((page_addr - size) < (stack_addr + sizeof(long long)))
			return -ENOMEM;

		if (__copy_to_user_inatomic(
			(unsigned long *)(page_addr - size), source, size))
			return -EFAULT;

		regs->ARM_pc = page_addr - size;
	} else
		return -EINVAL;

	return 0;
}

/**
 * This routines get the page containing the probe, maps it and
 * replaced the instruction at the probed address with specified
 * opcode.
 */
void __kprobes replace_original_insn(struct uprobe *uprobe,
				struct pt_regs *regs, kprobe_opcode_t opcode)
{
	kprobe_opcode_t *addr;
	struct page *page;

	page = find_get_page(uprobe->inode->i_mapping,
					uprobe->offset >> PAGE_CACHE_SHIFT);
	BUG_ON(!page);

	__lock_page(page);

	addr = (kprobe_opcode_t *)kmap_atomic(page, KM_USER1);
	addr = (kprobe_opcode_t *)((unsigned long)addr +
				 (unsigned long)(uprobe->offset & ~PAGE_MASK));
	*addr = opcode;
	flush_icache_range((unsigned long)addr, (unsigned long)(addr + 4));
	/*TODO: flush vma ? */
	kunmap_atomic(addr, KM_USER1);

	unlock_page(page);

	if (page)
		page_cache_release(page);
	regs->ARM_pc = (unsigned long)uprobe->kp.addr;
}
static int is_valid_user_regs(struct pt_regs *regs)
{
	if (user_mode(regs) && (regs->ARM_cpsr & PSR_I_BIT) == 0) {
		regs->ARM_cpsr &= ~(PSR_F_BIT | PSR_A_BIT);
		return 1;
	}

	/*
	 * Force CPSR to something logical...
	 */
	regs->ARM_cpsr &= PSR_f | PSR_s | (PSR_x & ~PSR_A_BIT) | PSR_T_BIT | MODE32_BIT;
	if (!(elf_hwcap & HWCAP_26BIT))
		regs->ARM_cpsr |= USR_MODE;

	return 0;
} 
/**
 * This routine provides the functionality of single stepping
 * out-of-line. If single stepping out-of-line cannot be achieved,
 * it replaces with the original instruction allowing it to single
 * step inline.
 */
static inline int prepare_singlestep_uprobe(struct kprobe *p, struct uprobe *uprobe,
				struct uprobe_ctlblk *ucb, struct pt_regs *regs)
{
	struct vm_area_struct *vma = NULL;
	struct uprobe_module *umodule = NULL;
	unsigned long vaddr = 0;
	int err = 0;

	if (uprobe == NULL && uprobe->inode == NULL) {
		printk("uprobe is null or inode is null\n");
		goto no_vma;
	}

	umodule = get_module_by_inode(uprobe->inode);

	if (umodule == NULL) {
		printk("umodule is null\n");
		goto no_vma;
	}
	if (umodule->xol_area == NULL) {
		umodule->xol_area = xol_alloc_area();
		if (umodule->xol_area == NULL) {
			printk("can't allocate out of line instruction memory\n");
			goto no_vma;
		}		
	}
	vaddr = xol_get_insn_slot(umodule->xol_area);
	umodule->vaddr = vaddr;
	if (vaddr == 0){
		printk("no xol slot\n");
		goto no_vma;
	}

	err = copy_insn_to_xol(uprobe, regs, vaddr, 0);

	ucb->uprobe_status = UPROBE_HIT_SS;
	ucb->vaddr = vaddr;
	ucb->xol_area = umodule->xol_area;

	if (!err) {
		kprobe_opcode_t *page_addr;
		unsigned long inst = 0;

		access_process_vm(current, vaddr, (void *)&inst, sizeof(inst), 0);
		printk("inst at 0x%x = %x pc=0x%x\n", vaddr, inst, regs->ARM_pc);

		access_process_vm(current, vaddr+4, (void *)&inst, sizeof(inst), 0);
		printk("inst at 0x%x = %x pc=0x%x\n", vaddr+4, inst, regs->ARM_pc);

		printk("is valid user: %d\n", is_valid_user_regs(regs));
		vma = find_vma(current->mm, vaddr);
		flush_user_insns(vma, vma->vm_start, vma->vm_end);
		regs->ARM_pc = vaddr;
	}
no_vma:
	if (err) {
		replace_original_insn(uprobe, regs, &uprobe->kp.opcode);
		ucb->uprobe_status = UPROBE_SS_INLINE;
	}
	ucb->singlestep_addr = regs->ARM_pc;
	return 0;
}

static void __kprobes singlestep_uprobe(struct kprobe *p, struct pt_regs *regs)
{
	regs->ARM_pc += 4;
	if (p->ainsn.insn_check_cc(regs->ARM_cpsr))
		p->ainsn.insn_handler(p, regs);

}


/*
 * uprobe_handler() executes the user specified handler and setup for
 * single stepping the original instruction either out-of-line or inline.
 */
static int __kprobes uprobe_handler(struct pt_regs *regs)
{
#if 1
	struct kprobe *p;
	kprobe_opcode_t *addr = NULL;
	struct uprobe_ctlblk *ucb = &uprobe_ctlblk;
	
	addr = (kprobe_opcode_t *)regs->ARM_pc;
	p = get_uprobe(addr);

	if (p) {
		if (current_uprobe) {
			/* Kprobe is pending, so we're recursing. */
			switch (ucb->uprobe_status) {
			case UPROBE_HIT_ACTIVE:
			case UPROBE_HIT_SSDONE:
				/* A pre- or post-handler probe got us here. */
				//kprobes_inc_nmissed_count(p);
				//save_previous_kprobe(kcb);
				set_uprobe_instance(p);
				ucb->uprobe_status = UPROBE_REENTER;
				singlestep_uprobe(p, regs);
				//restore_previous_kprobe(kcb);
				break;
			default:
				/* impossible cases */
				set_uprobe_instance(p);
				ucb->uprobe_status = UPROBE_REENTER;
				singlestep_uprobe(p, regs);
				printk("it should not be here bug\n");
				break;
				//BUG();
			}
		} else {
			set_uprobe_instance(p);
			ucb->uprobe_status = UPROBE_HIT_ACTIVE;

			/*
			 * If we have no pre-handler or it returned 0, we
			 * continue with normal processing.  If we have a
			 * pre-handler and it returned non-zero, it prepped
			 * for calling the break_handler below on re-entry,
			 * so get out doing nothing more here.
			 */
			if (!p->pre_handler || !p->pre_handler(p, regs)) {
				ucb->uprobe_status = UPROBE_HIT_SS;
				singlestep_uprobe(p, regs);
				if (p->post_handler) {
					ucb->uprobe_status = UPROBE_HIT_SSDONE;
					p->post_handler(p, regs, 0);
				}
				reset_uprobe_instance();
			}
		}
	} else if (current_uprobe) {
		/* We probably hit a jprobe.  Call its break handler. */
		/* Vincent not implement break handler yet
		if (cur->break_handler && cur->break_handler(cur, regs)) {
			kcb->kprobe_status = KPROBE_HIT_SS;
			singlestep(cur, regs, kcb);
			if (cur->post_handler) {
				kcb->kprobe_status = KPROBE_HIT_SSDONE;
				cur->post_handler(cur, regs, 0);
			}
		}*/
		reset_uprobe_instance();
	} else {
		/*
		 * The probe was removed and a race is in progress.
		 * There is nothing we can do about it.  Let's restart
		 * the instruction.  By the time we can restart, the
		 * real instruction will be there.
		 */
	}

#else
	struct kprobe *p;
	int ret = 0;
	kprobe_opcode_t *addr = NULL;
	struct uprobe_ctlblk *ucb = &uprobe_ctlblk;
	unsigned long limit;

	spin_lock_irqsave(&uprobe_lock, ucb->flags);
	/* preemption is disabled, remains disabled
	 * until we single step on original instruction.
	 */
	preempt_disable();

	addr = (kprobe_opcode_t *)regs->ARM_pc;

	p = get_uprobe(addr);
	if (!p) {

		if (*addr != KPROBE_BREAKPOINT_INSTRUCTION) {
			/*
			 * The breakpoint instruction was removed right
			 * after we hit it.  Another cpu has removed
			 * either a probepoint or a debugger breakpoint
			 * at this address.  In either case, no further
			 * handling of this interrupt is appropriate.
			 * Back up over the (now missing) int3 and run
			 * the original instruction.
			 */
			regs->ARM_pc -= sizeof(kprobe_opcode_t);
			ret = 1;
		}
		/* Not one of ours: let kernel handle it */
		goto no_uprobe;
	}

	if (p->opcode == KPROBE_BREAKPOINT_INSTRUCTION) {
		/*
		 * Breakpoint was already present even before the probe
		 * was inserted, this might break some compatability with
		 * other debuggers like gdb etc. We dont handle such probes.
		 */
		current_uprobe = NULL;
		goto no_uprobe;
	}

	ucb->curr_p = p;
	ucb->tsk = current;
	ucb->uprobe_status = UPROBE_HIT_ACTIVE;	
	ucb->uprobe_saved_epc = regs->ARM_pc;
	ucb->uprobe_saved_SR  = regs->ARM_cpsr;
	if (p->pre_handler && p->pre_handler(p, regs))
		/* handler has already set things up, so skip ss setup */
		return 1;

	//prepare_singlestep_uprobe(p, current_uprobe, ucb, regs);
	singlestep_uprobe(p, regs);
	/*
	 * Avoid scheduling the current while returning from
	 * kernel to user mode.
	 */
	clear_need_resched();
	return 1;

no_uprobe:
	spin_unlock_irqrestore(&uprobe_lock, ucb->flags);
	preempt_enable_no_resched();

	return ret;
#endif	
}

/*
 * Called after single-stepping.  p->addr is the address of the
 * instruction whose first byte has been replaced by the "int 3"
 * instruction.  To avoid the SMP problems that can occur when we
 * temporarily put back the original opcode to single-step, we
 * single-stepped a copy of the instruction.  The address of this
 * copy is p->ainsn.insn.
 *
 * This function prepares to return from the post-single-step
 * interrupt.  We have to fix up the stack as follows:
 *
 * 0) Typically, the new eip is relative to the copied instruction.  We
 * need to make it relative to the original instruction.  Exceptions are
 * return instructions and absolute or indirect jump or call instructions.
 *
 * 1) If the single-stepped instruction was pushfl, then the TF and IF
 * flags are set in the just-pushed eflags, and may need to be cleared.
 *
 * 2) If the single-stepped instruction was a call, the return address
 * that is atop the stack is the address following the copied instruction.
 * We need to make it the address following the original instruction.
 */
static void __kprobes resume_execution_user(struct kprobe *p,
		struct pt_regs *regs, struct uprobe_ctlblk *ucb)
{
	unsigned long orig_epc = ucb->uprobe_saved_epc;	
	struct vm_area_struct *vma = NULL;
	unsigned long inst = 0;
	

	printk("resume b:ARM_pc:%x ARM_cpsr:%x\n", regs->ARM_pc, regs->ARM_cpsr);
	if (is_valid_user_regs(regs))
	{		
		//vma = find_vma(current->mm, orig_epc + 4);
		regs->ARM_pc = orig_epc + 4;	
		regs->ARM_cpsr = ucb->uprobe_saved_SR;
		
		access_process_vm(current, regs->ARM_pc, (void *)&inst, sizeof(inst), 0);
				printk("resume at 0x%x = %x pc=0x%x\n", regs->ARM_pc, inst, regs->ARM_pc);
		//flush_user_insns(vma, vma->vm_start, vma->vm_end);
		printk("resume m: valid\n");
	}
	printk("resume a:ARM_pc:%x ARM_cpsr:%x\n", regs->ARM_pc, regs->ARM_cpsr);
}

/*
 * post_uprobe_handler(), executes the user specified handlers and
 * resumes with the normal execution.
 */
static inline int post_uprobe_handler(struct pt_regs *regs)
{
	struct kprobe *cur;
	struct uprobe_ctlblk *ucb;
	kprobe_opcode_t opcode;

	if (!current_uprobe)
		return 0;

	ucb = &uprobe_ctlblk;
	cur = ucb->curr_p;

	if (!cur || ucb->tsk != current)
		return 0;

	if (cur->post_handler) {
		if (ucb->uprobe_status == UPROBE_SS_INLINE)
			ucb->uprobe_status = UPROBE_SSDONE_INLINE;
		else
			ucb->uprobe_status = UPROBE_HIT_SSDONE;
		cur->post_handler(cur, regs, 0);
	}
	resume_execution_user(cur, regs, ucb);


	#if 0
	opcode = UPROBE_BREAKPOINT_INSTRUCTION_POST;
	if (ucb->uprobe_status == UPROBE_SSDONE_INLINE){
		
		replace_original_insn(current_uprobe, regs,
						&opcode);
	}	
	else {		
		//unlock_page(ucb->upage);
		//pte_unmap(ucb->upte);
	}
	
	//xol_free_insn_slot(ucb->vaddr, ucb->xol_area);
	#endif
	current_uprobe = NULL;
	spin_unlock_irqrestore(&uprobe_lock, ucb->flags);
	preempt_enable_no_resched();
	return 1;
}

static inline int uprobe_fault_handler(struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur;
	struct uprobe_ctlblk *ucb;
	int ret = 0;

	ucb = &uprobe_ctlblk;
	cur = ucb->curr_p;

	if (ucb->tsk != current || !cur)
		return 0;

	switch(ucb->uprobe_status) {
	case UPROBE_HIT_SS:		
		resume_execution_user(cur, regs, ucb);
		unlock_page(ucb->upage);
		pte_unmap(ucb->upte);		
		xol_free_insn_slot(ucb->vaddr, ucb->xol_area);
	case UPROBE_SS_INLINE:
		current_uprobe = NULL;
		ret = 1;
		spin_unlock_irqrestore(&uprobe_lock, ucb->flags);
		preempt_enable_no_resched();
		break;
	case UPROBE_HIT_ACTIVE:
	case UPROBE_SSDONE_INLINE:
	case UPROBE_HIT_SSDONE:
		if (cur->fault_handler && cur->fault_handler(cur, regs, trapnr))
			return 1;

		if (fixup_exception(regs))
			return 1;
		/*
		 * We must not allow the system page handler to continue while
		 * holding a lock, since page fault handler can sleep and
		 * reschedule it on different cpu. Hence return 1.
		 */
		return 1;
		break;
	default:
		break;
	}
	return ret;
}

/*
 * Wrapper routine to for handling exceptions.
 */
int __kprobes uprobe_exceptions_notify(struct pt_regs *regs, unsigned int instr)
{
	unsigned long flags;
	local_irq_save(flags);
	uprobe_handler(regs);
	local_irq_restore(flags);
	return 0;
}
int __kprobes uprobe_exceptions_notify_post(struct pt_regs *regs, unsigned int instr)
{
	unsigned long flags;
	local_irq_save(flags);
	post_uprobe_handler(regs);	
	local_irq_restore(flags);
	return 0;
}
#if 1//uretprobe
int __kprobes uretprobe_exceptions_notify(struct pt_regs *regs, unsigned int instr)
{
	unsigned long flags;
	local_irq_save(flags);
	regs->ARM_pc = ( long ) trampoline_handler(regs);
	local_irq_restore(flags);
	return 0;
}
#endif

void __kprobes arch_disarm_uprobe(struct kprobe *p, kprobe_opcode_t *address)
{
	*address = p->opcode;
	flush_insns(address, 1);
}

void __kprobes arch_arm_uprobe(kprobe_opcode_t *address)
{
	unsigned long addr = 0;

	addr = address;	
	*address = UPROBE_BREAKPOINT_INSTRUCTION;
	flush_insns(addr, 1);		
}

int __kprobes arch_copy_uprobe(struct kprobe *p, kprobe_opcode_t *address)
{
	kprobe_opcode_t insn;
	kprobe_opcode_t original_insn;
	kprobe_opcode_t tmp_insn[MAX_INSN_SIZE];
	int is;
	unsigned long addr = (unsigned long)address;
	
	if ((addr & 0x3) || (in_exception_text(address)))
		return -EINVAL;

	insn = *address;
	original_insn = *address;
	p->opcode = insn;
	p->ainsn.insn = tmp_insn;
	switch (arm_uprobe_decode_insn(insn, &p->ainsn)) {
	case INSN_REJECTED:	/* not supported */
		printk("ins not support\n");
		return -EINVAL;

	case INSN_GOOD:		/* instruction uses slot */
	case INSN_GOOD_NO_SLOT: /* instruction doesn't need insn slot */		
		//printk("ins good\n");
		p->ainsn.insn = get_insn_slot();
		if (!p->ainsn.insn)
			return -ENOMEM;
		for (is = 0; is < MAX_INSN_SIZE; ++is) 
			p->ainsn.insn[is] = tmp_insn[is];			

		flush_insns(p->ainsn.insn, MAX_INSN_SIZE);
		break;
	#if 0	
	case INSN_GOOD_NO_SLOT:	/* instruction doesn't need insn slot */
		printk("ins good no slot\n");
		p->ainsn.insn = NULL;
		break;
	#endif	

	}

	return 0;
}
