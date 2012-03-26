/*
 * arch/arm/include/asm/kprobes.h
 *
 * Copyright (C) 2006, 2007 Motorola Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef _ARM_KPROBES_H
#define _ARM_KPROBES_H

#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/percpu.h>

#define __ARCH_WANT_KPROBES_INSN_SLOT
#define MAX_INSN_SIZE			2
#define MAX_STACK_SIZE			64	/* 32 would probably be OK */

/*
 * This undefined instruction must be unique and
 * reserved solely for kprobes' use.
 */
#define KPROBE_BREAKPOINT_INSTRUCTION	0xe7f001f8
#if UPROBE_PATCH
#define UPROBE_BREAKPOINT_INSTRUCTION		0xe7f001f9
#define UPROBE_BREAKPOINT_INSTRUCTION_POST	0xe7f001f7
#define URETPROBE_BREAKPOINT_INSTRUCTION	0xe7f001f6 //uretprobe
#endif


#define regs_return_value(regs)		((regs)->ARM_r0)
#define flush_insn_slot(p)		do { } while (0)
#define kretprobe_blacklist_size	0

typedef u32 kprobe_opcode_t;

struct kprobe;
typedef void (kprobe_insn_handler_t)(struct kprobe *, struct pt_regs *);
typedef unsigned long (kprobe_check_cc)(unsigned long);
/* Architecture specific copy of original instruction. */
struct arch_specific_insn {
	kprobe_opcode_t		*insn;
	kprobe_insn_handler_t	*insn_handler;
	kprobe_check_cc         *insn_check_cc;
	#if UPROBE_PATCH
	int probe_type;
	#endif

};

struct prev_kprobe {
	struct kprobe *kp;
	unsigned int status;
};

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	unsigned int kprobe_status;
	struct prev_kprobe prev_kprobe;
	struct pt_regs jprobe_saved_regs;
	char jprobes_stack[MAX_STACK_SIZE];
};

#if UPROBE_PATCH
/* per user probe control block */
struct uprobe_ctlblk {
	unsigned long uprobe_status;
	unsigned long uprobe_saved_SR;
	unsigned long uprobe_saved_epc;
	unsigned long singlestep_addr;
	unsigned long flags;
	struct kprobe *curr_p;
	pte_t *upte;
	struct page *upage;
	struct task_struct *tsk;
	unsigned long vaddr;
	void *xol_area;
};
#endif

void arch_remove_kprobe(struct kprobe *);
void kretprobe_trampoline(void);

int kprobe_fault_handler(struct pt_regs *regs, unsigned int fsr);
int kprobe_exceptions_notify(struct notifier_block *self,
			     unsigned long val, void *data);

#if UPROBE_PATCH
extern int uprobe_exceptions_notify(struct pt_regs *regs, unsigned int instr);
extern int uprobe_exceptions_notify_post(struct pt_regs *regs, unsigned int instr);
extern int uretprobe_exceptions_notify(struct pt_regs *regs, unsigned int instr);
#endif

enum kprobe_insn {
	INSN_REJECTED,
	INSN_GOOD,
	INSN_GOOD_NO_SLOT
};

enum kprobe_insn arm_kprobe_decode_insn(kprobe_opcode_t,
					struct arch_specific_insn *);
void __init arm_kprobe_decode_init(void);
#if UPROBE_PATCH
enum kprobe_insn arm_uprobe_decode_insn(kprobe_opcode_t,
					struct arch_specific_insn *);
#endif
#endif /* _ARM_KPROBES_H */
