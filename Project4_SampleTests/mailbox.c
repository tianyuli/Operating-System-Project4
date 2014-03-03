/**
* Adapted from CS-502 Project #3, Fall 2006
*	originally submitted by Cliff Lindsay
* Modified for CS-502, Summer 2011 by Alfredo Porras
* Adapted for CS-502 at Cisco Systems, Fall 2011
*
*/

#include "mailbox.h"

#define __NR_cs3013_syscall1  349
#define __NR_cs3013_syscall2  350
#define __NR_cs3013_syscall3  351

/**
 * Functions for msgs
 * 
 * */
long SendMsg(pid_t dest, void *msg, int len, bool block) {
  return syscall(349, dest, msg, len, block);
} 	// int SendMsg

long RcvMsg(pid_t *sender, void *msg, int *len, bool block){
  return syscall(350, sender, msg, len, block);
}	// int RcvMsg

/**
 * functions for maintaining mailboxes
 * 
 * */
long ManageMailbox(bool stop, int *count){
  return syscall(351, stop, count);
}	// int ManageMailbox



