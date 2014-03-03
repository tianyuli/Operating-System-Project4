#include <stdio.h>
#include <stdlib.h>
#include "mailbox.h"
#include <sys/types.h>
#include <unistd.h>

int main (){
	printf("sending 35 messages to myself, the mailbox will be full after number 32\n");
	char mesg[] = "This is a test";
	int i;
	int ret;
	int mypid = getpid();
	for (i = 0; i < 35; i++){
		printf("Sending Message to myself. #%d\n", i+1);
		ret = SendMsg(mypid, mesg, 15, false);
		if (ret){
		  printf("Send failed: error = %d, mypid = %d, count = %d\n", ret, mypid, i+1);
		}
	}
	for (i = 0; i < 35; i++){
		void *msg[128];
		int len;
		bool block = true;
		int sender;
		ret = RcvMsg(&sender,msg,&len,block);
		printf("Message received. #%d\n", i+1);
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d, count = %d\n", (char *) msg, sender, len, mypid, ret, i+1);
	}
	return 0;
}
