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
#include <linux/types.h>
#include <linux/signal.h>
#include <stdbool.h>
#include <linux/unistd.h>
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
#define HASHTABLE_SIZE	1024
#define FALSE 0
#define TRUE   1

/* define data structure for each mail */
typedef struct message_struct {
	void* content;
	pid_t sender;
	int len;
	struct message_struct* next;
} message;

/* define data structure for mailbox */
typedef struct mailbox_linked_list {
	pid_t pid;
	message* msg;
	int size;
	bool full;
	bool stop;
	struct mailbox_linked_list* next;
} mailbox;

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall1)(void);
asmlinkage long (*ref_sys_cs3013_syscall2)(void);
asmlinkage long (*ref_sys_cs3013_syscall3)(void);

struct kmem_cache* mailCache;
struct kmem_cache* mbCache;
struct kmem_cache* msgCache;

static mailbox* all[HASHTABLE_SIZE]; //pointer to table

message* temp;// = (message*) kmem_cache_alloc(mailCache, GFP_KERNEL);

/**
 * hash: form hash value for given pid
 */
unsigned hash (pid_t pid){
	unsigned hashval = pid * 31;
	return hashval % HASHTABLE_SIZE;
}

/**
 * create a message with given information
 */
message* create_message(pid_t sender, int len, void *msg) {
	//allocate memory for mail
	message* thisMail = (message*) kmem_cache_alloc(mailCache, GFP_KERNEL);
	thisMail->content = msg;
	thisMail->len = len;
	thisMail->sender = sender;
	thisMail->next = NULL;
	return thisMail;
}

/**
 * look for mailbox with given pid in hashtable
 */
mailbox* get_mailbox(pid_t pid) {
	printk("pid in get= %d", pid);
	mailbox* mb;
	for (mb = all[hash(pid)]; mb != NULL; mb = mb->next){
		if (pid == mb->pid) return mb; //found
	}
	return NULL; //not found
}

/**
 * create new mailbox in hashtable for given pid
 */
mailbox* create_mailbox(pid_t pid) {
	mailbox* mb = (mailbox*) kmem_cache_alloc(mbCache, GFP_KERNEL);
	unsigned hashval;

	mb->stop = FALSE;
	mb->full = FALSE;
	mb->size = 0;
	mb->pid = pid;
	
	hashval = hash(pid);
	mb->next = all[hashval];
	all[hashval] = mb;
	return mb;
}

/**
 * add the given message to given mailbox
 */
void add_message(mailbox* mb, message* message) {
	temp = mb->msg;
	while (temp->next != NULL) {
		temp = temp->next;
	}
	
	temp->next = message;
	//mb->msg = temp;
	
	(mb->size)++;
	if (mb->size == MAX_MSG_SIZE) {
		mb->full = TRUE;
	}
	//kmem_cache_free(mailCache, temp);
	
}

/**
 * remove oldest message from the given mailbox
 */
void rm_message(mailbox* mb) {
	temp = mb->msg;
	while (temp->next != NULL) {
		temp = temp->next;
	}
	temp = NULL;
	
	//mb->msg = temp;
	(mb->size)--;
	if (mb->full) {
		mb->full = FALSE;
	}
	//kmem_cache_free(mailCache, temp);
}
	
	
		
		
	

/**
 * send message to given destination
 */
asmlinkage long sys_SendMsg(pid_t dest, void *a_msg, int len, bool block){
	//get pid of sender
	pid_t my_pid = current->pid;
	
	//pid_t dest;
	void* msg = kmem_cache_alloc(msgCache, GFP_KERNEL);
	//int len;
	//bool block;
	message* this_mail;
	int ret;
	printk(KERN_INFO "Reach4");
	//check if arguments are valid
	/*if (ret = copy_from_user(&dest, &a_dest, sizeof(pid_t)))
		return a_dest;*/
	if (copy_from_user(msg, a_msg, len))
		return 3000;
	/*if (copy_from_user(&len, &a_len, sizeof(int)))
		return 4000;
	if (copy_from_user(&block, &a_block, sizeof(bool)))
		 return MSG_ARG_ERROR;*/

	//check if destination is valid
	//int existence = kill(dest, 0);
	printk(KERN_INFO "Reach3");
	mailbox* dest_mailbox = get_mailbox(dest);
	
	if (/*existence != 0 ||*/ dest <= 0 /*|| process && mailbox deleted*/) //kernel tasks, system processes
		return MAILBOX_INVALID;
		
	if (dest_mailbox == NULL) {
		dest_mailbox = create_mailbox(dest);
		if (dest_mailbox == NULL) return 98765;
	}
	if (block == FALSE && (dest_mailbox->full == TRUE))
		return MAILBOX_FULL;
	if (dest_mailbox->stop)
		return MAILBOX_STOPPED;
	if ((len > MAX_MSG_SIZE) || (len < 0))
		return MSG_LENGTH_ERROR;
	//any other error return MAILBOX_ERROR
		
	printk(KERN_INFO "Reach1");
	this_mail = create_message(my_pid, len, msg);
	printk(KERN_INFO "Reach2");
	printk(KERN_INFO "pid in send = %d", dest);
	add_message(dest_mailbox, this_mail);
	
	//successfully sent
	return 0;
}

/**
 * receive message from given sender
 */
asmlinkage long sys_RcvMsg(pid_t *sender, void *msg, int *len, bool block){

	//bool a_block;
	//if (copy_from_user(&a_block, &block, sizeof(bool))) return MSG_ARG_ERROR;

	pid_t my_pid = current->pid;
	printk(KERN_INFO "\"'Hello world?!' More like 'Goodbye, world!' EXTERMINATE!\" -- Dalek");
	printk(KERN_INFO "pid before get = %d", my_pid);
	mailbox* mb = get_mailbox(my_pid);
	
	if (mb == NULL) return 12345;
	
	if ((block == NO_BLOCK) && (mb->size == 0))
		return MAILBOX_EMPTY;
	if (mb->stop && (mb->size == 0))
		return MAILBOX_STOPPED;

	while ((block == BLOCK) && (mb->size == 0));

	pid_t *a_sender = &(mb->pid);
	void *a_msg = mb->msg->content;
	int *a_len = &(mb->msg->len);

	if ((*a_len > MAX_MSG_SIZE) || (*a_len < 0))
		return MSG_LENGTH_ERROR;

	
	if ((copy_to_user(sender, a_sender, sizeof(pid_t)))
	|| (copy_to_user(msg, a_msg, (long unsigned)a_len)) 
	|| (copy_to_user(len, a_len, sizeof(int))))
		 return MSG_ARG_ERROR;
	//any other error return MAILBOX_ERROR
	
	rm_message(mb);
		
	//successful
	return 0;
}

/**
 * functions for maintaining mailboxes
 * 
 * */
asmlinkage long sys_ManageMailbox(bool stop, int *count){
	pid_t my_pid = current->pid;
	
	bool a_stop;
	if (copy_from_user(&stop, &a_stop, sizeof(bool)))
		return MSG_ARG_ERROR;
		
	mailbox* mb = get_mailbox(my_pid);
	if (a_stop) {
		mb->stop = TRUE;
	}
	int a_count = mb->size;
	
	if (copy_to_user(count, &a_count, sizeof(int)))
		return MSG_ARG_ERROR;

	return 0;
	
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
	ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];
	ref_sys_cs3013_syscall3 = (void *)sys_call_table[__NR_cs3013_syscall3];

	/* Replace the existing system calls */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)sys_SendMsg;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)sys_RcvMsg;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)sys_ManageMailbox;
	enable_page_protection();

	//mailCache and mbCache are global variables
	mailCache = kmem_cache_create("mail", sizeof(message), 0, 0, NULL);
	mbCache = kmem_cache_create("mb", sizeof(mailbox), 0, 0, NULL);
	msgCache = kmem_cache_create("msg", MAX_MSG_SIZE, 0, 0, NULL);
	
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
	kmem_cache_destroy(mbCache);
	kmem_cache_destroy(msgCache);

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


