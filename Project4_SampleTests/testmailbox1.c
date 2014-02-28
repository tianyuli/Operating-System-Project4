/* Alfredo Porras
 * July 12th, 2011
 * CS 3013
 * Project 4 - test program 1
 * Tests if messages can be sent and received.
 */

#include "mailbox.h"
#include <stdio.h>
#define __NR_cs3013_syscall1  349
#define __NR_cs3013_syscall1  350
#define __NR_cs3013_syscall1  351
int main() {
  int childPID = fork();
  
  if(childPID == 0){
    pid_t sender;
    void *msg[128];
    int len;
    bool block = true;
	int this;
    this = RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
	int mypid = getpid();
    printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, this);
  }
  else{
    char mesg[] = "I am your father";
    printf("Sending Message to child.\n");
	int ret;
	int fatherpid = getpid();
    if (ret = SendMsg(childPID, mesg, 17, false)){
      printf("Send failed: error = %d, childPID = %d, fatherpid = %d\n", ret, childPID, fatherpid);
    }
  }
  return 0;
}
