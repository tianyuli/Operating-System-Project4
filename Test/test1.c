#include <stdio.h>
#include <stdlib.h>
#include "mailbox.h"
#include <sys/types.h>
#include <unistd.h>

int main(){
	char mesg[] = "This is a test";
	printf("Sending Message to myself.\n");
	int ret;
	int mypid = getpid();
	if (ret = SendMsg(mypid, mesg, 15, false)){
	  printf("Send failed: error = %d, mypid = %d", ret, mypid);
	}
	void *msg[128];
    int len;
    bool block = true;
	int sender;
    ret = RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
    printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	return 0;
}
