//@author Xi Wen(xwen) && Tianyu Li(tli) && Xia Li(xli2)

#include <stdio.h>
#include <stdlib.h>
#include "mailbox.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

/** This program test for a simple send and receive using mailbox **/
int main(){
	char mesg[] = "This is a test";
	printf("Sending Message to myself.\n");
	int ret;
	int mypid = getpid();
	ret = SendMsg(mypid, mesg, 15, false);
	if (ret){
	  printf("Send failed: error = %d, mypid = %d", ret, mypid);
	}
	void *msg[128];
    int len;
    bool block = true;
	int sender;
    ret = RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
    printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	printf("---------------------------RESULT-----------------------------------------------\n");
	if ((sender == mypid) && (strcmp((char*)msg, mesg) == 0) && (len == 15)) 
		printf("TEST PASSED!\n");
	else printf("TEST FAILED!\n");
	return 0;
}

