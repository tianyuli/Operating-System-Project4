#include <stdio.h>
#include <stdlib.h>
#include "mailbox.h"
#include <sys/types.h>
#include <unistd.h>

int main (){
	char mesg[] = "This is a test";
	int mypid = getpid();
	int ret;
	int count = 0;

	/*******************************test1************************************/
	printf("TEST1\n");
	printf("Sending Message to pid = -3, expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(-3, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count ++;
	}
	/*******************************test2************************************/
	printf("TEST2\n");
	printf("Sending message to my child (which does not exist) expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(mypid+1, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count ++;
	}
	/*******************************test3************************************/
	printf("TEST3\n");
	printf("Sending message to kernel task (pid == 1) expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(1, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count ++;
	}
	/*******************************test4************************************/
	printf("TEST4\n");
	printf("Try to receive message from a empty mailbox, expect MAILBOX_EMPTY (1002)\n");
	printf("Sending Message to myself.\n");
	ret = SendMsg(mypid, mesg, 15, false);
	if (ret){
	  printf("Send failed: error = %d, mypid = %d", ret, mypid);
	}
	void *msg[128];
    int len;
    bool block = true;
	int sender;
    ret = RcvMsg(&sender,msg,&len,block);
	if (ret){
		printf("Receive failed for the first time! error = %d\n", ret);
		count --;
	}
    else{
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	}
	printf("Now try receive message again, should get error MAILBOX_EMPTY (1002)\n");
	ret = RcvMsg(&sender,msg,&len,block);
	if (ret) {
		printf("Receive failed for the second time! error = %d\n", ret);
		if (ret == MAILBOX_EMPTY) count ++;
	}
	else {
		printf("ret = %d\n", ret);
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	}
	printf("Now try receive message again, should get error MAILBOX_EMPTY (1002)\n");
	ret = RcvMsg(&sender,msg,&len,block);
	if (ret) {
		printf("Receive failed for the second time! error = %d\n", ret);
		if (ret == MAILBOX_EMPTY) count ++;
	}
	else {
		printf("ret = %d\n", ret);
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	}
	
	/*
	void *msg[128];
    int len;
    bool block = true;
	int sender;
    ret = RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
    printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	*/
	return 0;
	

}
