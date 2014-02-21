//@author Xi Wen(xwen) && Tianyu Li(tli) && Xia Li(xli2)

// We need to define __KERNEL__ and MODULE to be in Kernel space
// If they are defined, undefined them and define them again:
#undef __KERNEL__
#undef MODULE

#define __KERNEL__ 
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#include "mailbox.h"
#include <linux/slab.h>
/*
#include <linux/sched.h> //header defining task_struct
#include <linux/list.h> //macros for linked list
#include <asm-generic/current.h> //header defining "current"
#include <asm-generic/cputime.h> //cputime_to_usecs()
#include <linux/time.h> //timespec_to_ns()
//#include <asm-generic/uaccess.h> //copy_from_user; copy_to_user
#include <asm-generic/errno.h>
#include <linux/mm.h>
*/

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall1)(void);

kmem_cache_t* mailCache;

asmlinkage long sys_SendMsg(pid_t dest, void *msg, int len, bool block){
	if (/*dest invalid*/ || /*process && mailbox deleted*/) //kernel tasks, system processes
		return MAILBOX_INVALID;
	if (block == FALSE && /*dest mailbox full*/)
		return MAILBOX_FULL;
	if (/*mailbox stopped*/)
		return MAILBOX_STOPPED;
	if ((len > MAX_MSG_SIZE) || (len < 0))
		return MSG_LENGTH_ERROR;
	if (/*any pointer argument to any message or mailbox call is invalid*/) //copy_to_user and copy_from_user fail
		return MSG_ARG_ERROR;
	//anyother error return MAILBOX_ERROR
		
	
	
	//allocate memory for mail
	void* thisMail = kmem_cache_alloc(mailCache, GFP_KERNEL);
	
		
	//successfully sent
	return 0;
}

asmlinkage long sys_RcvMsg(pid_t *sender, void *msg, int *len, bool block){
	if (block == FALSE && /*mailbox empty*/)
		return MAILBOX_EMPTY;
	if (/*mailbox stopped*/ && /*mailbox empty*/)
		return MAILBOX_STOPPED;
	if ((len > MAX_MSG_SIZE) || (len < 0))
		return MSG_LENGTH_ERROR;
	if (/*any pointer argument to any message or mailbox call is invalid*/) //copy_to_user and copy_from_user fail
		return MSG_ARG_ERROR;
		
		
	//anyother error return MAILBOX_ERROR
		
		
	//successful
	return 0;
}

/**
 * functions for maintaining mailboxes
 * 
 * */
asmlinkage long sys_ManageMailbox(bool stop, int *count){
	if (stop); //any attempt to send a future message to this mailbox results in an error to the sending task
	
}

static unsigned long **find_sys_call_table(void) {
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close) {
			printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX", (unsigned long) sct);
			return sct;
		}

	offset += sizeof(void *);
	}

	return NULL;
}	// static unsigned long **find_sys_call_table(void)


static void disable_page_protection(void) {
	/*
	Control Register 0 (cr0) governs how the CPU operates.

	Bit #16, if set, prevents the CPU from writing to memory marked as
	read only. Well, our system call table meets that description.
	But, we can simply turn off this bit in cr0 to allow us to make
	changes. We read in the current value of the register (32 or 64
	bits wide), and AND that with a value where all bits are 0 except
	the 16th bit (using a negation operation), causing the write_cr0
	value to have the 16th bit cleared (with all other bits staying
	the same. We will thus be able to write to the protected memory.

	It's good to be the kernel!
	*/

	write_cr0 (read_cr0 () & (~ 0x10000));

}	//static void disable_page_protection(void)


static void enable_page_protection(void) {
	/*
	See the above description for cr0. Here, we use an OR to set the
	16th bit to re-enable write protection on the CPU.
	*/

	write_cr0 (read_cr0 () | 0x10000);

}	// static void enable_page_protection(void)

static int __init interceptor_start(void) {
	/* Find the system call table */
	if(!(sys_call_table = find_sys_call_table())) {
		/* Well, that didn't work.
		Cancel the module loading step. */
		return -1;
	}

	/* Store a copy of all the existing functions */
	ref_sys_cs3013_syscall1 = (void *)sys_call_table[__NR_cs3013_syscall1];

	/* Replace the existing system calls */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)sys_SendMsg;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)sys_RcvMsg;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)sys_ManageMailbox;
	enable_page_protection();

	//mailCache is a global variable
	mailCache = kmem_cache_create(mailbox, MAX_SIZE_MSG + sizeof(pid_t) + sizeof(len), 0, 0, NULL);
	
	/* And indicate the load was successful */
	printk(KERN_INFO "Loaded interceptor!");

	return 0;
}	// static int __init interceptor_start(void)


static void __exit interceptor_end(void) {
	/* If we don't know what the syscall table is, don't bother. */
	if(!sys_call_table)
		return;
		
	//done with mailnoxes
	kmem_cache_destroy(mailCache);

	/* Revert all system calls to what they were before we began. */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall2;
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall3;
	enable_page_protection();

	printk(KERN_INFO "Unloaded interceptor!");
}	// static void __exit interceptor_end(void)

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);


