/*
 * User-space Probes (UProbes)
 * kernel/uprobes.c
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
 * Copyright (C) IBM Corporation, 2006
 *
 * 2006-Mar Created by Prasanna S Panchamukhi <prasanna@xxxxxxxxxx>
 * User-space probes initial implementation.
 */
#include <linux/kprobes.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <asm-generic/sections.h>
#include <asm/cacheflush.h>
#include <asm/errno.h>
#include <asm/kdebug.h>
#include <asm/traps.h>

#define UPROBE_HASH_BITS 6
#define UPROBE_TABLE_SIZE (1 << UPROBE_HASH_BITS)

/* user space probes lists */
static struct list_head uprobe_module_list;
static struct hlist_head uprobe_table[UPROBE_TABLE_SIZE];
typedef int (*process_uprobe_func_t)(struct uprobe *uprobe, kprobe_opcode_t *address);
DEFINE_SPINLOCK(uprobe_lock); /* Protects uprobe_table*/
DEFINE_MUTEX(uprobe_mutex); /* Protects uprobe_module_table */
struct uprobe *current_uprobe = NULL;

static int map_uprobe_page(struct page *page, struct uprobe *uprobe, process_uprobe_func_t process_kprobe_user);
int insert_kprobe_user(struct uprobe *uprobe, kprobe_opcode_t *address);
static void  flush_vma(struct address_space *mapping, struct page *page, struct uprobe *uprobe);
struct uprobe_module *get_module_by_inode(struct inode *inode);


static inline void insert_readpage_uprobe(struct page *page,
	struct address_space *mapping, struct uprobe *uprobe)
{
	unsigned long page_start = page->index << PAGE_CACHE_SHIFT;
	unsigned long page_end = page_start + PAGE_SIZE;

	if ((uprobe->offset >= page_start) && (uprobe->offset < page_end)) {
		map_uprobe_page(page, uprobe, insert_kprobe_user);
		flush_vma(mapping, page, uprobe);
	}
}

/**
 *  This function hooks the readpages() of all modules that have active
 *  probes on them. The original readpages() is called for the given
 *  inode/address_space to actually read the pages into the memory.
 *  Then all probes that are specified on these pages are inserted.
 */
static int __kprobes uprobe_readpages(struct file *file,
				struct address_space *mapping,
				struct list_head *pages, unsigned nr_pages)
{
	int retval = 0;
	struct page *page;
	struct uprobe_module *umodule;
	struct uprobe *uprobe = NULL;
	struct hlist_node *node;

	mutex_lock(&uprobe_mutex);

	umodule = get_module_by_inode(file->f_dentry->d_inode);
	if (!umodule) {
		/*
		 * No module associated with this file, call the
		 * original readpages().
		 */
		retval = mapping->a_ops->readpages(file, mapping,
							pages, nr_pages);
		goto out;
	}

	/* call original readpages() */
	retval = umodule->ori_a_ops->readpages(file, mapping, pages, nr_pages);
	if (retval < 0)
		goto out;

	/*
	 * TODO: Walk through readpages page list and get
	 * pages with probes instead of find_get_page().
	 */
	hlist_for_each_entry(uprobe, node, &umodule->ulist_head, ulist) {
		page = find_get_page(mapping,
				uprobe->offset >> PAGE_CACHE_SHIFT);
		if (!page)
			continue;

		if (!uprobe->kp.opcode)
			insert_readpage_uprobe(page, mapping, uprobe);
		page_cache_release(page);
	}

out:
	mutex_unlock(&uprobe_mutex);

	return retval;
}

/**
 *  This function hooks the readpage() of all modules that have active
 *  probes on them. The original readpage() is called for the given
 *  inode/address_space to actually read the pages into the memory.
 *  Then all probes that are specified on this page are inserted.
 */
int __kprobes uprobe_readpage(struct file *file, struct page *page)
{
	int retval = 0;
	struct uprobe_module *umodule;
	struct uprobe *uprobe = NULL;
	struct hlist_node *node;
	struct address_space *mapping = file->f_dentry->d_inode->i_mapping;

	mutex_lock(&uprobe_mutex);

	umodule = get_module_by_inode(file->f_dentry->d_inode);
	if (!umodule) {
		/*
		 * No module associated with this file, call the
		 * original readpage().
		 */
		retval = mapping->a_ops->readpage(file, page);
		goto out;
	}

	/* call original readpage() */
	retval = umodule->ori_a_ops->readpage(file, page);
	if (retval < 0)
		goto out;

	hlist_for_each_entry(uprobe, node, &umodule->ulist_head, ulist) {
		if (!uprobe->kp.opcode)
			insert_readpage_uprobe(page, mapping, uprobe);
	}

out:
	mutex_unlock(&uprobe_mutex);

	return retval;
}

/*
 * Aggregate handlers for multiple uprobes support - these handlers
 * take care of invoking the individual uprobe handlers on p->list
 */
static int __kprobes aggr_user_pre_handler(struct kprobe *p,
 struct pt_regs *regs)
{
	 struct kprobe *kp;

	 list_for_each_entry(kp, &p->list, list) {
		 if (kp->pre_handler) {
			 set_uprobe_instance(kp);
			 if (kp->pre_handler(kp, regs))
				 return 1;
		 }
	 }
	 return 0;
}

static void __kprobes aggr_user_post_handler(struct kprobe *p,
 struct pt_regs *regs, unsigned long flags)
{
	struct kprobe *kp;

	list_for_each_entry(kp, &p->list, list) {
		if (kp->post_handler) {
			set_uprobe_instance(kp);
			kp->post_handler(kp, regs, flags);
		}
	}
}

static int __kprobes aggr_user_fault_handler(struct kprobe *p,
 struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur;

	/*
	* if we faulted "during" the execution of a user specified
	* probe handler, invoke just that probe's fault handler
	*/
	cur = &current_uprobe->kp;
	if (cur && cur->fault_handler)
		if (cur->fault_handler(cur, regs, trapnr))
			return 1;
		
	return 0;
}

/**
 * This routine looks for an existing uprobe at the given offset and inode.
 * If it's found, returns the corresponding kprobe pointer.
 * This should be called with uprobe_lock held.
 */
static struct kprobe __kprobes *get_kprobe_user(struct inode *inode,
 unsigned long offset)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *kpr;
	struct uprobe *uprobe;

	head = &uprobe_table[hash_ptr((kprobe_opcode_t *)
				(((unsigned long)inode) * offset), UPROBE_HASH_BITS)];

	hlist_for_each_entry(p, node, head, hlist) {
		if (p->pre_handler == aggr_user_pre_handler) {
			kpr = list_entry(p->list.next, typeof(*kpr), list);
			uprobe = container_of(kpr, struct uprobe, kp);
		} else
			uprobe = container_of(p, struct uprobe, kp);

		if ((uprobe->inode == inode) && (uprobe->offset == offset))
			return p;
	}

	return NULL;
}

/**
 * Finds a uprobe at the specified user-space address in the current task.
 * Points current_uprobe at that uprobe and returns the corresponding kprobe.
 */
struct kprobe __kprobes *get_uprobe(void *addr)
{
#if 1
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct inode *inode;
	unsigned long offset;
	struct kprobe *p, *kpr;
	struct uprobe *uprobe;

	vma = find_vma(mm, (unsigned long)addr);

	BUG_ON(!vma);	/* this should not happen, not in our memory map */

	offset = (unsigned long)addr - (vma->vm_start +
						(vma->vm_pgoff << PAGE_SHIFT));
	if (!vma->vm_file)
		return NULL;

	inode = vma->vm_file->f_dentry->d_inode;

	p = get_kprobe_user(inode, offset);
	if (!p)
		return NULL;

	if (p->pre_handler == aggr_user_pre_handler) {
		/*
		 * Walk the uprobe aggregate list and return firt
		 * element on aggregate list.
		 */
		kpr = list_entry((p)->list.next, typeof(*kpr), list);
		uprobe = container_of(kpr, struct uprobe, kp);
	} else
		uprobe = container_of(p, struct uprobe, kp);

	
	//if (uprobe)
	//	current_uprobe = uprobe;

	return p;

#else
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct inode *inode;
	unsigned long offset;
	struct kprobe *p, *kpr;
	struct uprobe *uprobe;

	vma = find_vma(mm, (unsigned long)addr);

	BUG_ON(!vma); /* this should not happen, not in our memory map */

	offset = (unsigned long)addr - vma->vm_start +
	(vma->vm_pgoff << PAGE_SHIFT);
	if (!vma->vm_file)
		return NULL;

	inode = vma->vm_file->f_dentry->d_inode;

	p = get_kprobe_user(inode, offset);
	if (!p)
		return NULL;

	if (p->pre_handler == aggr_user_pre_handler) {
		/*
		* Walk the uprobe aggrigate list and return firt
		* element on aggrigate list.
		*/
		kpr = list_entry((p)->list.next, typeof(*kpr), list);
		uprobe = container_of(kpr, struct uprobe, kp);
	} else
		uprobe = container_of(p, struct uprobe, kp);

	if (uprobe)
		current_uprobe = uprobe;

	return p;
#endif
}

/*
 * Keep all fields in the kprobe consistent
 */
static inline void copy_uprobe(struct kprobe *old_p, struct kprobe *p)
{
	memcpy(&p->opcode, &old_p->opcode, sizeof(kprobe_opcode_t));
	memcpy(&p->ainsn, &old_p->ainsn, sizeof(struct arch_specific_insn));
}

/*
 * Fill in the required fields of the "manager uprobe". Replace the
 * earlier kprobe in the hlist with the manager uprobe
 */
static inline void add_aggr_uprobe(struct kprobe *ap, struct kprobe *p)
{
	copy_uprobe(p, ap);
	ap->addr = p->addr;
	ap->pre_handler = aggr_user_pre_handler;
	ap->post_handler = aggr_user_post_handler;
	ap->fault_handler = aggr_user_fault_handler;

	INIT_LIST_HEAD(&ap->list);
	list_add(&p->list, &ap->list);

	hlist_replace_rcu(&p->hlist, &ap->hlist);
}

/*                                            
 * This is the second or subsequent uprobe at the address - handle
 * the intricacies
 */
static int __kprobes register_aggr_uprobe(struct kprobe *old_p,
 struct kprobe *p)
{
	int ret = 0;
	struct kprobe *ap;

	if (old_p->pre_handler == aggr_user_pre_handler) {
		copy_uprobe(old_p, p);
		list_add(&p->list, &old_p->list);
	} else {
		ap = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
		if (!ap)
			return -ENOMEM;
		add_aggr_uprobe(ap, old_p);
		copy_uprobe(ap, p);
		list_add(&p->list, &old_p->list);
	}
	return ret;
}

/**
 * Saves the original instruction in the uprobe structure and
 * inserts the breakpoint at the given address.
 */
int __kprobes insert_kprobe_user(struct uprobe *uprobe,
 kprobe_opcode_t *address)
{
	int ret = 0;

	ret = arch_copy_uprobe(&uprobe->kp, address);	
	if (ret) {
		printk("Breakpoint already present\n");
		return ret;
	}
	arch_arm_uprobe(address);

	return 0;
}

/**
 * Wait for the page to be unlocked if someone else had locked it,
 * then map the page and insert or remove the breakpoint.
 */
static int __kprobes map_uprobe_page(struct page *page, struct uprobe *uprobe,
			process_uprobe_func_t process_kprobe_user)
{
	int ret = 0;
	kprobe_opcode_t *uprobe_address;

	if (!page)
	{
		//printk("page is Null\n");
		return -EINVAL; /* TODO: more suitable errno */
	}
	wait_on_page_locked(page);
	/* could probably retry readpage here. */
	if (!PageUptodate(page))
	{		
		//printk("Page is not upto date\n");
		return -EINVAL; /* TODO: more suitable errno */
	}
	lock_page(page);

	uprobe_address = (kprobe_opcode_t *)kmap(page);
	uprobe_address = (kprobe_opcode_t *)((unsigned long)uprobe_address +
											(uprobe->offset & ~PAGE_MASK));
	ret = (*process_kprobe_user)(uprobe, uprobe_address);
	kunmap(page);
	unlock_page(page);

	return ret;
}

/**
 * flush_vma walks through the list of process private mappings,
 * gets the vma containing the offset and flush all the vma's
 * containing the probed page.
 */
static void __kprobes flush_vma(struct address_space *mapping,
 struct page *page, struct uprobe *uprobe)
{
	struct vm_area_struct *vma = NULL;
	struct prio_tree_iter iter;
	struct prio_tree_root *head = &mapping->i_mmap;
	struct mm_struct *mm;
	unsigned long start, end, offset = uprobe->offset;

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, head, offset, offset) {
		mm = vma->vm_mm;
		start = vma->vm_start - (vma->vm_pgoff << PAGE_SHIFT);
		end = vma->vm_end - (vma->vm_pgoff << PAGE_SHIFT);

		if ((start + offset) < end)
			flush_icache_user_range(vma, page,
										(unsigned long)uprobe->kp.addr,
										sizeof(kprobe_opcode_t));
	}
	spin_unlock(&mapping->i_mmap_lock);
}

/**
 * Walk the uprobe_module_list and return the uprobe module with matching
 * inode.
 */
struct uprobe_module __kprobes *get_module_by_inode(struct inode *inode)
{
	struct uprobe_module *umodule;

	list_for_each_entry(umodule, &uprobe_module_list, mlist) {
	if (umodule->nd.path.dentry->d_inode == inode)
		return umodule;
	}

	return NULL;
}

/**
 * Gets exclusive write access to the given inode to ensure that the file
 * on which probes are currently applied does not change. Use the function,
 * deny_write_access_to_inode() we added in fs/namei.c.
 */
static inline int ex_write_lock(struct inode *inode)
{
	return deny_write_access_to_inode(inode);
}

/**
 * Called when removing user space probes to release the write lock on the
 * inode.
 */
static inline int ex_write_unlock(struct inode *inode)
{
	atomic_inc(&inode->i_writecount);
	return 0;
}

/**
 * Add uprobe and uprobe_module to the appropriate hash list.
 */
static void __kprobes get_inode_ops(struct uprobe *uprobe,
 struct uprobe_module *umodule)
{
	struct address_space *as;


	INIT_HLIST_HEAD(&umodule->ulist_head);
	hlist_add_head(&uprobe->ulist, &umodule->ulist_head);
	list_add(&umodule->mlist, &uprobe_module_list);
	as = umodule->nd.path.dentry->d_inode->i_mapping;
	umodule->ori_a_ops = as->a_ops;
	umodule->user_a_ops = *as->a_ops;
	umodule->user_a_ops.readpage = uprobe_readpage;
	umodule->user_a_ops.readpages = uprobe_readpages;
	as->a_ops = &umodule->user_a_ops;	
}

/*
 * Removes the specified uprobe from either aggrigate uprobe list
 * or individual uprobe hash table.
 */

static int __kprobes remove_uprobe(struct uprobe *uprobe)
{
	struct kprobe *old_p, *list_p, *p;
	int ret = 0;

	p = &uprobe->kp;
	old_p = get_kprobe_user(uprobe->inode, uprobe->offset);
	if (unlikely(!old_p))
		return 0;

	if (p != old_p) {
		list_for_each_entry(list_p, &old_p->list, list)
		if (list_p == p)
		/* kprobe p is a valid probe */
		goto valid_p;
		return 0;
	}

	valid_p:
	if ((old_p == p) ||
			((old_p->pre_handler == aggr_user_pre_handler) &&
			(p->list.next == &old_p->list) &&
			(p->list.prev == &old_p->list))) {
		/* Only probe on the hash list */
		ret = 1;
		hlist_del(&old_p->hlist);
		if (p != old_p) {
			list_del(&p->list);
			kfree(old_p);
		}
	} else
		list_del(&p->list);

	return ret;
}

/*
 * Disarms the probe and frees the corresponding instruction slot.
 */
static int __kprobes remove_kprobe_user(struct uprobe *uprobe,
 kprobe_opcode_t *address)
{
	struct kprobe *p = &uprobe->kp;

	arch_disarm_uprobe(p, address);
	arch_remove_kprobe(p);

	return 0;
}

/*
 * Adds the given uprobe to the uprobe_hash table if it is
 * the first probe to be inserted at the given address else
 * adds to the aggrigate uprobe's list.
 */
static int __kprobes insert_uprobe(struct uprobe *uprobe)
{
	struct kprobe *old_p;
	int ret = 0;
	unsigned long offset = uprobe->offset;
	unsigned long inode = (unsigned long) uprobe->inode;
	struct hlist_head *head;
	unsigned long flags;

	spin_lock_irqsave(&uprobe_lock, flags);
	uprobe->kp.nmissed = 0;

	old_p = get_kprobe_user(uprobe->inode, uprobe->offset);

	if (old_p)
		register_aggr_uprobe(old_p, &uprobe->kp);
	else {
		head = &uprobe_table[hash_ptr((kprobe_opcode_t *)
		(offset * inode), UPROBE_HASH_BITS)];
		INIT_HLIST_NODE(&uprobe->kp.hlist);
		hlist_add_head(&uprobe->kp.hlist, head);
		ret = 1;
	}

	spin_unlock_irqrestore(&uprobe_lock, flags);

	return ret;
}

/**
 * unregister_uprobe: Disarms the probe, removes the uprobe
 * pointers from the hash list and unhooks readpage routines.
 */
void __kprobes unregister_uprobe(struct uprobe *uprobe)
{
	struct address_space *mapping;
	struct uprobe_module *umodule;
	struct page *page;
	unsigned long flags;
	int ret = 0;

	if (!uprobe->inode)
		return;

	mapping = uprobe->inode->i_mapping;

	page = find_get_page(mapping, uprobe->offset >> PAGE_CACHE_SHIFT);

	spin_lock_irqsave(&uprobe_lock, flags);
	ret = remove_uprobe(uprobe);
	spin_unlock_irqrestore(&uprobe_lock, flags);

	mutex_lock(&uprobe_mutex);
	if (!(umodule = get_module_by_inode(uprobe->inode)))
		goto out;

	hlist_del(&uprobe->ulist);
	if (hlist_empty(&umodule->ulist_head)) {
		list_del(&umodule->mlist);
		umodule->nd.path.dentry->d_inode->i_mapping->a_ops = umodule->ori_a_ops;
		ex_write_unlock(uprobe->inode);
		path_put(&umodule->nd.path);
		kfree(umodule);
	}

out:
	mutex_unlock(&uprobe_mutex);
	if (ret)
		ret = map_uprobe_page(page, uprobe, remove_kprobe_user);

	if (ret == -EINVAL)
		return;
	/*
	* TODO: unregister_uprobe should not fail, need to handle
	* if it fails.
	*/
	flush_vma(mapping, page, uprobe);

	if (page)
		page_cache_release(page);
}

/**
 * register_uprobe(): combination of inode and offset is used to
 * identify each probe uniquely. Each uprobe can be found from the
 * uprobes_hash table by using inode and offset. register_uprobe(),
 * inserts the breakpoint at the given address by locating and mapping
 * the page. return 0 on success and error on failure.
 */
int __kprobes register_uprobe(struct uprobe *uprobe)
{
	struct address_space *mapping;
	struct uprobe_module *umodule = NULL;
	struct inode *inode;
	struct nameidata nd;
	struct page *page;
	int error = 0;

	INIT_HLIST_NODE(&uprobe->ulist);

	/*
	* TODO: Need to calculate the absolute file offset for dynamic
	* shared libraries.
	*/
	//printk("register_uprobe: 0x%x pathname %s\n", uprobe, uprobe->pathname);
	if ((error = path_lookup(uprobe->pathname, LOOKUP_FOLLOW, &nd)))
	{
		printk("path_lookup fail\n");
		return error;
	}
	mutex_lock(&uprobe_mutex);

	inode = nd.path.dentry->d_inode;
	error = ex_write_lock(inode);
	if (error)
	{
		printk("write lock fail\n");
		goto out;
	}
	
	/*
	* Check if there are probes already on this application and
	* add the corresponding uprobe to per application probe's list.
	*/
	umodule = get_module_by_inode(inode);
	if (!umodule) {

		/* vincent */
		//error = arch_alloc_insn(&uprobe->kp);
		//error = arch_prepare_kprobe(&uprobe->kp);
		//if (error)
		//goto out;

		/*
		* Allocate a uprobe_module structure for this
		* application if not allocated before.
		*/
		umodule = kzalloc(sizeof(struct uprobe_module), GFP_KERNEL);
		if (!umodule) {
			printk("umodule, memory allocate fail\n");
			error = -ENOMEM;
			ex_write_unlock(inode);
			arch_remove_kprobe(&uprobe->kp);
			goto out;
		}
		memcpy(&umodule->nd, &nd, sizeof(struct nameidata));
		get_inode_ops(uprobe, umodule);
	} else {
		path_put(&nd.path);
		ex_write_unlock(inode);
		hlist_add_head(&uprobe->ulist, &umodule->ulist_head);
	}
	mutex_unlock(&uprobe_mutex);

	uprobe->inode = inode;
	mapping = inode->i_mapping;

	page = find_get_page(mapping, (uprobe->offset >> PAGE_CACHE_SHIFT));

	if (insert_uprobe(uprobe))
		error = map_uprobe_page(page, uprobe, insert_kprobe_user);

	/*
	* If error == -EINVAL, return success, probes will inserted by
	* readpage hooks.
	* TODO: Use a more suitable errno?
	*/
	if (error == -EINVAL)
	{
		//printk("can't find page for probed address\n");
		error = 0;
	}
	flush_vma(mapping, page, uprobe);

	if (page)
		page_cache_release(page);

	return error;
out:
	printk("register uprobe get out\n");
	path_put(&nd.path);
	mutex_unlock(&uprobe_mutex);

	return error;
}

static struct undef_hook uprobes_break_hook = {
	.instr_mask	= 0xffffffff,
	.instr_val	= UPROBE_BREAKPOINT_INSTRUCTION,
	.cpsr_mask	= MODE_MASK,
	.cpsr_val	= USR_MODE,
	.fn		= uprobe_exceptions_notify,
};

static struct undef_hook uprobes_break_post_hook = {
	.instr_mask	= 0xffffffff,
	.instr_val	= UPROBE_BREAKPOINT_INSTRUCTION_POST,
	.cpsr_mask	= MODE_MASK,
	.cpsr_val	= USR_MODE,
	.fn		= uprobe_exceptions_notify_post,
};

static struct undef_hook uretprobes_break = {
	.instr_mask = 0xffffffff,
	.instr_val	= URETPROBE_BREAKPOINT_INSTRUCTION,
	.cpsr_mask	= MODE_MASK,
	.cpsr_val	= USR_MODE,
	.fn		= uretprobe_exceptions_notify,
};



void init_uprobes(void)
{
	int i;

	register_undef_hook(&uprobes_break_hook);
	//register_undef_hook(&uprobes_break_post_hook);	
	register_undef_hook(&uretprobes_break);

	/* FIXME allocate the probe table, currently defined statically */
	/* initialize all list heads */
	for (i = 0; i < UPROBE_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&uprobe_table[i]);

	INIT_LIST_HEAD(&uprobe_module_list);
}

EXPORT_SYMBOL_GPL(register_uprobe);
EXPORT_SYMBOL_GPL(unregister_uprobe);
