/*	
 * User-space BreakPoint support (user_bkpt) -- Allocation of instruction
 * slots for execution out of line (XOL)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2009, 2010
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

/*
 * Every probepoint gets its own slot.  Once it's assigned a slot, it
 * keeps that slot until the probepoint goes away. Only definite number
 * of slots are allocated.
 */
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define MAX_UINSN_BYTES 0x20
#define USER_BKPT_XOL_SLOT_BYTES (MAX_UINSN_BYTES)

#define UINSNS_PER_PAGE	(PAGE_SIZE/USER_BKPT_XOL_SLOT_BYTES)
#define MAX_USER_BKPT_XOL_SLOTS UINSNS_PER_PAGE

struct user_bkpt_xol_area {
	spinlock_t lock;	/* protects bitmap and slot (de)allocation*/
	unsigned long *bitmap;	/* 0 = free slot */

	/*
	 * We keep the vma's vm_start rather than a pointer to the vma
	 * itself.  The probed process or a naughty kernel module could make
	 * the vma go away, and we must handle that reasonably gracefully.
	 */
	unsigned long vaddr;		/* Page(s) of instruction slots */
};

static int xol_add_vma(struct user_bkpt_xol_area *area)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct file *file;
	unsigned long addr;

	mm = get_task_mm(current);
	if (!mm)
		return -ESRCH;

	down_write(&mm->mmap_sem);
	/*
	 * Find the end of the top mapping and skip a page.
	 * If there is no space for PAGE_SIZE above
	 * that, mmap will ignore our address hint.
	 *
	 * We allocate a "fake" unlinked shmem file because
	 * anonymous memory might not be granted execute
	 * permission when the selinux security hooks have
	 * their way.
	 */
	vma = rb_entry(rb_last(&mm->mm_rb), struct vm_area_struct, vm_rb);
	addr = vma->vm_end + PAGE_SIZE;
	
	file = shmem_file_setup("/uprobes/xol", PAGE_SIZE, vma->vm_flags);
	if (!file) {
		printk(KERN_ERR "user_bkpt_xol failed to setup shmem_file "
			"while allocating vma for pid/tgid %d/%d for "
			"single-stepping out of line.\n",
			current->pid, current->tgid);
		goto fail;
	}
	
	addr = do_mmap_pgoff(file, addr, PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, 0);
	printk("xol_add_vma:addr=0x%x\n", addr);
	fput(file);

	if (addr & ~PAGE_MASK) {
		printk(KERN_ERR "user_bkpt_xol failed to allocate a vma for "
				"pid/tgid %d/%d for single-stepping out of "
				"line.\n", current->pid, current->tgid);
		goto fail;
	}
	vma = find_vma(mm, addr);

	/* Don't expand vma on mremap(). */
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTCOPY;
	area->vaddr = vma->vm_start;
	printk("start:0x%x end:0x%x\n", vma->vm_start, vma->vm_end);
	up_write(&mm->mmap_sem);
	
	mmput(mm);
	return 0;

fail:
	up_write(&mm->mmap_sem);
	mmput(mm);
	return -ENOMEM;
}

/**
 * xol_alloc_area - Allocate process's user_bkpt_xol_area.
 * This area will be used for storing instructions for execution out of
 * line.
 */
void *xol_alloc_area(void)
{
	struct user_bkpt_xol_area *area = NULL;

	area = kzalloc(sizeof(*area), GFP_USER);
	if (unlikely(!area))
		return NULL;

	area->bitmap = kzalloc(BITS_TO_LONGS(UINSNS_PER_PAGE) * sizeof(long),
								GFP_USER);

	if (!area->bitmap)
		goto fail;
	if (xol_add_vma(area)) {
		kfree(area->bitmap);
		goto fail;
	}
	spin_lock_init(&area->lock);
	return (void *)area;

fail:
	kfree(area);
	return NULL;
}

void xol_free_area(void *xol_area)
{
	struct user_bkpt_xol_area *area;

	area = (struct user_bkpt_xol_area *)xol_area;
	kfree(area->bitmap);
	kfree(area);
}

/*
 * Find a slot
 *  - searching in existing vmas for a free slot.
 *  - If no free slot in existing vmas, return 0;
 *  called with lock acquired.
 */
static unsigned long xol_take_insn_slot(struct user_bkpt_xol_area *area)
{
	unsigned long slot_addr;
	int slot_nr;

	slot_nr = find_first_zero_bit(area->bitmap, UINSNS_PER_PAGE);
	slot_nr = 1;
	if (slot_nr < UINSNS_PER_PAGE) {
		set_bit(slot_nr, area->bitmap);
		slot_addr = area->vaddr +
				(slot_nr * USER_BKPT_XOL_SLOT_BYTES);
		return slot_addr;
	}

	return 0;
}

/**
 * xol_get_insn_slot - If user_bkpt was not allocated a slot, then
 * allocate a slot. If user_bkpt_insert_bkpt is already called, (i.e
 * user_bkpt.vaddr != 0) then copy the instruction into the slot.
 * Returns the allocated slot address or 0.
 * @user_bkpt: probepoint information
 * @xol_area refers the unique per process user_bkpt_xol_area for
 * this process.
 */
unsigned long xol_get_insn_slot(void *xol_area)
{
	unsigned long xol_vaddr = 0;
	struct user_bkpt_xol_area *area;
	unsigned long flags;
	int len;

	area = (struct user_bkpt_xol_area *)xol_area;
	if (unlikely(!area))
		return 0;

	spin_lock_irqsave(&area->lock, flags);
	xol_vaddr = xol_take_insn_slot(area);
	spin_unlock_irqrestore(&area->lock, flags);

	return xol_vaddr;
}

/**
 * xol_free_insn_slot - If slot was earlier allocated by
 * @xol_get_insn_slot(), make the slot available for
 * subsequent requests.
 * @slot_addr: slot address as returned by
 * @xol_get_insn_area().
 * @xol_area refers the unique per process user_bkpt_xol_area for
 * this process.
 */
void xol_free_insn_slot(unsigned long slot_addr, void *xol_area)
{
	struct user_bkpt_xol_area *area;
	unsigned long vma_end;
	int found = 0;

	area = (struct user_bkpt_xol_area *)xol_area;
	if (unlikely(!slot_addr || IS_ERR_VALUE(slot_addr)))
		return;

	if (unlikely(!area))
		return;

	vma_end = area->vaddr + PAGE_SIZE;
	if (area->vaddr <= slot_addr && slot_addr < vma_end) {
		int slot_nr;
		unsigned long offset = slot_addr - area->vaddr;
		unsigned long flags;

		BUG_ON(offset % USER_BKPT_XOL_SLOT_BYTES);

		slot_nr = offset / USER_BKPT_XOL_SLOT_BYTES;
		BUG_ON(slot_nr >= UINSNS_PER_PAGE);

		spin_lock_irqsave(&area->lock, flags);
		clear_bit(slot_nr, area->bitmap);
		spin_unlock_irqrestore(&area->lock, flags);
		found = 1;
	}

	if (!found)
		printk(KERN_ERR "%s: no XOL vma for slot address %#lx\n",
						__func__, slot_addr);
}

/**
 * xol_validate_vaddr - Verify if the specified address is in an
 * executable vma, but not in an XOL vma.
 *	- Return 0 if the specified virtual address is in an
 *	  executable vma, but not in an XOL vma.
 *	- Return 1 if the specified virtual address is in an
 *	  XOL vma.
 *	- Return -EINTR otherwise.(i.e non executable vma, or
 *	  not a valid address
 * @pid: the probed process
 * @vaddr: virtual address of the instruction to be validated.
 * @xol_area refers the unique per process user_bkpt_xol_area for
 * this process.
 */
 
#if 0
int xol_validate_vaddr(struct pid *pid, unsigned long vaddr, void *xol_area)
{
	struct user_bkpt_xol_area *area;
	struct task_struct *tsk;
	unsigned long vma_end;
	int result;

	area = (struct user_bkpt_xol_area *) xol_area;
	tsk = pid_task(pid, PIDTYPE_PID);
	result = user_bkpt_validate_insn_addr(tsk, vaddr);
	if (result != 0)
		return result;

	if (unlikely(!area))
		return 0;

	vma_end = area->vaddr + PAGE_SIZE;
	if (area->vaddr <= vaddr && vaddr < vma_end)
		result = 1;

	return result;
}
#endif
