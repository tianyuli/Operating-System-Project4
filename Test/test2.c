#include <stdio.h>
#include <stdlib.h>
#include "mailbox.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

/** This program test for correct handle of full mailbox
 ** It also test for error code 1001 MAILBOX_FULL	
 **/
int main (){
	printf("sending 35 messages to myself, the mailbox will be full after number 32\n");
	char mesg[] = "This is a test";
	int i;
	int ret;
	int mypid = getpid();
	int rcvCount = 0;
	int failCount = 0;
	for (i = 0; i < 35; i++){
		printf("Sending Message to myself. #%d\n", i+1);
		ret = SendMsg(mypid, mesg, 15, false);
		if (ret){
			printf("Send failed: error = %d, mypid = %d, count = %d\n", ret, mypid, i+1);
			if (ret == MAILBOX_FULL) failCount ++;
		}
	}
	for (i = 0; i < 35; i++){
		void *msg[128];
		int len;
		bool block = true;
		int sender;
		ret = RcvMsg(&sender, msg, &len, block);
		printf("Message received. #%d\n", i+1);
		printf("Message: %s, sender = %d, len = %d, return = %d, count = %d\n", (char *) msg, sender, len, ret, i+1);
		if ((sender == mypid) && (strcmp((char*)msg, mesg) == 0) && (len == 15)) rcvCount++;
	}
	printf("---------------------------RESULT-----------------------------------------------\n");
	if ((rcvCount == 35) && (failCount == 3)) printf("TEST PASSED!\n");
	else printf("TEST FAILED! rcvCount = %d, sentFailCount = %d\n", rcvCount, failCount);
	return 0;
}
