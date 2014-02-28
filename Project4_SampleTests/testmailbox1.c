/* Alfredo Porras
 * July 12th, 2011
 * CS 3013
 * Project 4 - test program 1
 * Tests if messages can be sent and received.
 */

#include "mailbox.h"
#include <stdio.h>

int main() {
  int childPID = fork();
  
  if(childPID == 0){
    pid_t sender;
    void *msg[128];
    int len;
    bool block = true;
    RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
    printf("Message: %s\n", (char *) msg);
  }
  else{
    char mesg[] = "I am your father";
    printf("Sending Message to child.\n");
	int ret;
    if (ret = SendMsg(childPID, mesg, 17, false)){
      printf("Send failed: error = %d\n", ret);
    }
  }
  return 0;
}
