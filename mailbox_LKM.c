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
#include <linux/sched.h>
#include <linux/spinlock.h>
/*
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
#define MAX_MB_SIZE 32

/* define data structure for each mail */
typedef struct message_struct {
	void* content;
	pid_t sender;
	int len;
	struct message_struct* next;
} message;

/* define data structure for mailbox */
typedef struct mailbox_linked_list {
	//wait_queue_head_t wqh;
	pid_t pid;
	message* msg;
	int size;
	spinlock_t lock;
	bool full;
	bool stop;
	struct mailbox_linked_list* next;
} mailbox;

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall1)(void);
asmlinkage long (*ref_sys_cs3013_syscall2)(void);
asmlinkage long (*ref_sys_cs3013_syscall3)(void);
asmlinkage long (*ref_sys_exit)(int error_code);
asmlinkage long (*ref_sys_exit_group)(int error_code);
struct kmem_cache* mailCache;
struct kmem_cache* mbCache;
struct kmem_cache* msgCache;

mailbox* all[HASHTABLE_SIZE]; //pointer to table
message** temp;// = (message*) kmem_cache_alloc(mailCache, GFP_KERNEL);

/**
 * hash: form hash value for given pid
 */
unsigned hash (pid_t pid){
	unsigned hashval = pid * 31;
	return hashval % HASHTABLE_SIZE;
}

/*initialize hashtable*/
void init_ht(void){
	//spin_lock(lock);
	int i;
	for (i = 0; i < HASHTABLE_SIZE; i++){
		all[i] = NULL;
	}
	//spin_unlock(lock);
}

/*free given mail*/
void free_mail(message* mail){
	if (mail == NULL) return;
	free_mail(mail->next);
	if (mail->content != NULL){
		kmem_cache_free(msgCache, mail->content);
	}
	if (mail != NULL) {
		kmem_cache_free(mailCache, mail);
	}
}

/*free given mailbox*/
void free_mb(mailbox* mb){
	if (mb == NULL)	return;
	free_mb(mb->next);
	free_mail(mb->msg);
	if (mb != NULL) {
		kmem_cache_free(mbCache, mb);
	}
}

/* free hashtable */
void free_ht(void){
	int i;
	for (i = 0; i < HASHTABLE_SIZE; i++){
		free_mb(all[i]);
	}
}


/*allocate memory space for a new mail*/
message* new_mail(void){
	return (message*) kmem_cache_alloc(mailCache, GFP_KERNEL);
}

/*allocate memory space for a new mailbox*/
mailbox* new_mb(void){
	return (mailbox*) kmem_cache_alloc(mbCache, GFP_KERNEL);
}

void* new_msg(void){
	return kmem_cache_alloc(msgCache, GFP_KERNEL);
}

/**
 * create a message with given information
 */
message* create_message(pid_t sender, int len, void *msg) {
	//allocate memory for mail
	message* thisMail = new_mail();
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
	mailbox* mb;
	int count = 0;
	//printk("pid in get= %d, hashpid = %u", pid, hash(pid));
	//printk("all[hashpid] = %p, all[hashpid]->pid = %d", all[hash(pid)], all[hash(pid)]->pid);
	for (mb = all[hash(pid)]; mb != NULL; mb = mb->next){
		if (pid == mb->pid){
			printk("found mailbox for pid %d, mailbox # = %d", pid, mb->pid);
		    return mb; //found
		}
		count++;
		printk("count=%d", count);
	}
	//printk("did not find mailbox :(");
	return NULL; //not found
}

/**
 * create new mailbox in hashtable for given pid
 */
mailbox* create_mailbox(pid_t pid) {
	mailbox* mb = new_mb();
	unsigned hashval;
	
	//init_waitqueue_head(&(mb->wqh));
	mb->stop = FALSE;
	mb->full = FALSE;
	mb->size = 0;
	mb->pid = pid;
	mb->msg = NULL;
	
	hashval = hash(pid);
	//spin_lock(lock);
	mb->next = all[hashval];
	all[hashval] = mb;
	//spin_unlock(lock);
	printk("created mailbox at hashval = %d, address = %p, address next = %p", hashval, mb, mb->next);
	return mb;
}

/**
 * add the given message to given mailbox
 */
void add_message(mailbox** mb, message** message) {
	if ((*message) == NULL){
		printk("adding message, msg == NULL");		
		return;
	}
	//acquire spin lock
	//spin_lock(&(*mb)->wqh.lock);
	//spin_lock(lock);
	temp = &((*mb)->msg);
	if ((*temp) == NULL) {
		(*temp) = (*message);
		(*temp)->next = NULL;
	}
	else {
		while ((*temp)->next != NULL) {
			(*temp) = (*temp)->next;
		}
		(*temp)->next = (*message);
	}
	//mb->msg = temp;
	
	((*mb)->size)++;
	if ((*mb)->size == MAX_MB_SIZE) {
		(*mb)->full = TRUE;
	}
	printk("added message to mailbox at address %p, message address %p, temp = %p", *mb, (*message), temp);
	//kmem_cache_free(mailCache, temp);
	//wake_up_locked(&(*mb)->wqh);
	//spin_unlock(&(*mb)->wqh.lock);
	//spin_unlock(lock);
}

/**
 * remove oldest message from the given mailbox
 */
void rm_message(mailbox** mb) {
	(*temp) = (*mb)->msg;
	printk("*temp is %p", temp);
	if ((*temp) == NULL)
		return;
	//acquire spin lock
	//spin_lock(&(*mb)->wqh.lock);
	//spin_lock(lock);
	printk("rm msg: *temp not NULL");
	(*mb)->msg = (*mb)->msg->next;
	printk("about to free *temp");
	if ((*temp) != NULL)
		kmem_cache_free(mailCache, (*temp));
	printk("freed *temp");
	((*mb)->size)--;
	if ((*mb)->full) {
		(*mb)->full = FALSE;
	}
	printk("rm over");
	//kmem_cache_free(mailCache, temp);
	//wake_up_locked(&(*mb)->wqh);
	//spin_unlock(&(*mb)->wqh.lock);
	//spin_unlock(lock);
}

message* get_msg(mailbox** mb){
	printk("got message, msg address = %p", (*mb)->msg);
	return (*mb)->msg;
	rm_message(mb);
}
		

/**
 * send message to given destination
 */
asmlinkage long sys_SendMsg(pid_t dest, void *a_msg, int len, bool block){
	//get pid of sender
	pid_t my_pid = current->pid;
	
	//spin_lock(lock);
	
	void* msg = new_msg();
	message* this_mail;
	mailbox* dest_mailbox;
	struct task_struct* dest_ts;
	int existence;
	printk(KERN_INFO "Reach4");

	if (copy_from_user(msg, a_msg, len))
		return MSG_ARG_ERROR;

	//check if destination is valid
	if (dest <= 0) return MAILBOX_INVALID;
	//find task struct for destination pid
	dest_ts = pid_task(find_vpid(dest), PIDTYPE_PID);
	// find_task_by_vpid(dest);
	if (dest_ts == NULL) return MAILBOX_INVALID;
	//state not 0 or kernel task, invalid dest
	existence = dest_ts->state;
	if ((existence != 0) || (dest_ts->mm == NULL)) return MAILBOX_INVALID;
	printk(KERN_INFO "Reach3");
	
	//get destination mailbox
	dest_mailbox = get_mailbox(dest);
		
	if (dest_mailbox == NULL) {
		dest_mailbox = create_mailbox(dest);
		if (dest_mailbox == NULL) return 98765;
	}
	if ((block == TRUE) && (dest_mailbox->full == TRUE)){
		//wait until not full and send message
	}
	else if (block == FALSE && (dest_mailbox->full == TRUE))
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

	spin_lock_init(&(dest_mailbox->lock));
	spin_lock(&(dest_mailbox->lock));
	add_message(&dest_mailbox, &this_mail);
	spin_unlock(&(dest_mailbox->lock));
	
	//spin_unlock(lock);
	//successfully sent
	return 0;
}

/**
 * receive message from given sender
 */
asmlinkage long sys_RcvMsg(pid_t *sender, void *msg, int *len, bool block){

	//spin_lock(lock);
	//bool a_block;
	//if (copy_from_user(&a_block, &block, sizeof(bool))) return MSG_ARG_ERROR;
	pid_t my_pid = current->pid;
	mailbox* mb = NULL;
	message* this_mail;
	pid_t *a_sender;
	void *a_msg;
	int *a_len;
	//while ((block == BLOCK) && (mb == NULL));
	printk(KERN_INFO "pid before get = %d", my_pid);
	
	//while (mb->size == 0);
	while ((block == BLOCK) && (mb == NULL)){
		mb = get_mailbox(my_pid);
	}
	if (mb == NULL) return 12345;
	
	if ((block == NO_BLOCK) && (mb->size == 0))
		return MAILBOX_EMPTY;
	if (mb->stop && (mb->size == 0))
		return MAILBOX_STOPPED;

	while ((block == BLOCK) && (mb->size == 0)) {
		printk("LLLLLLLLLLLOOOPPPP");
	}	
	printk("mailbox size = %d, mailbox address = %p", mb->size, mb);
	spin_lock_init(&(mb->lock));
	spin_lock(&(mb->lock));
	this_mail = get_msg(&mb);
	spin_unlock(&(mb->lock));

	if (this_mail == NULL) return 1155665;

	a_sender = &(this_mail->sender);
	a_msg = this_mail->content;
	a_len = &(this_mail->len);
	printk("a_sender = %d, a_msg = %p, a_len = %d", *a_sender, a_msg, *a_len);

	if (((*a_len) > MAX_MSG_SIZE) || ((*a_len) < 0))
		return MSG_LENGTH_ERROR;

	printk("got here yooooooooooooooooo");
	if ((copy_to_user(sender, a_sender, sizeof(pid_t))))
		return 2000;
	if ((copy_to_user(msg, a_msg, MAX_MSG_SIZE)))
		return 3000;
	if ((copy_to_user(len, a_len, sizeof(int))))
		 return MSG_ARG_ERROR;
	//any other error return MAILBOX_ERROR
	printk("copy succeeded");
	//rm_message(&mb);
	printk("read to return");

	//spin_lock(lock);
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
	mailbox* mb;
	int a_count;
	if (copy_from_user(&stop, &a_stop, sizeof(bool)))
		return MSG_ARG_ERROR;
		
	mb = get_mailbox(my_pid);
	if (a_stop) {
		mb->stop = TRUE;
	}
	a_count = mb->size;
	
	if (copy_to_user(count, &a_count, sizeof(int)))
		return MSG_ARG_ERROR;

	return 0;
}

/*
asmlinkage long sys_mb_exit(int error_code){
	pid_t mypid = current->pid;
	mailbox *mb = get_mailbox(mypid);
	if (mb != NULL){
	//here is some comment
		free_mail(mb->msg);
		//here is some comment
		if (mb != NULL)
			//here is some comment
			kmem_cache_free(mbCache, mb);
	}
	(*ref_sys_exit)(error_code);
	return 0;
}

asmlinkage long sys_mb_exit_group(int error_code){
	pid_t mypid = current->pid;
	mailbox *mb = get_mailbox(mypid);
	if (mb != NULL){
		//here is some comment
		free_mail(mb->msg);
		//here is some comment
		if (mb != NULL)
			//here is some comment
			kmem_cache_free(mbCache, mb);
	}
	(*ref_sys_exit_group)(error_code);
	return 0;
}

*/

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
	//ref_sys_exit = (void *)sys_call_table[__NR_exit];
	//ref_sys_exit_group = (void *)sys_call_table[__NR_exit_group];

	/* Replace the existing system calls */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)sys_SendMsg;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)sys_RcvMsg;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)sys_ManageMailbox;
	//sys_call_table[__NR_exit] = (unsigned long *)sys_mb_exit;
	//sys_call_table[__NR_exit_group] = (unsigned long *)sys_mb_exit_group;
	enable_page_protection();

	//mailCache and mbCache are global variables
	//spin_lock_init(lock);
	//static DEFINE_SPINLOCK(lock);
	mailCache = kmem_cache_create("mail", sizeof(message), 0, 0, NULL);
	mbCache = kmem_cache_create("mb", sizeof(mailbox), 0, 0, NULL);
	msgCache = kmem_cache_create("msg", MAX_MSG_SIZE, 0, 0, NULL);
	init_ht();
	//all = kmalloc(HASHTABLE_SIZE * sizeof(mailbox*), GFP_KERNEL);
	
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
	if ((temp) != NULL){
		if (*temp != NULL)
			kmem_cache_free(mailCache, (*temp));
	}
	free_ht();

	/* Revert all system calls to what they were before we began. */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)ref_sys_cs3013_syscall3;
	//sys_call_table[__NR_exit] = (unsigned long *)ref_sys_exit;
	//sys_call_table[__NR_exit_group] = (unsigned long *)ref_sys_exit_group;
	enable_page_protection();

	printk(KERN_INFO "Unloaded interceptor!");
}	// static void __exit interceptor_end(void)

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);


