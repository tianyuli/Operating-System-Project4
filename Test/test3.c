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
	printf("\n###TEST1###\n");
	printf("Sending Message to pid = -3, expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(-3, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count++;
	}
	/*******************************test2************************************/
	printf("\n###TEST2###\n");
	printf("Sending message to my child (which does not exist) expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(mypid+1, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count++;
	}
	/*******************************test3************************************/
	printf("\n###TEST3###\n");
	printf("Sending message to kernel task (pid == 1) expect MAILBOX_INVALID (1004)\n");
	ret = SendMsg(1, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d\n", ret);
		if (ret == 1004) count++;
	}
	/*******************************test4************************************/
	printf("\n###TEST4###\n");
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
		count--;
	}
    else{
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	}
	printf("Now try receive message again, should get error MAILBOX_EMPTY (1002)\n");
	ret = RcvMsg(&sender,msg,&len,false);
	if (ret) {
		printf("Receive failed for the second time! error = %d\n", ret);
		if (ret == MAILBOX_EMPTY) count++;
	}
	

	/*******************************test5************************************/
	printf("###TEST5###\n");
	printf("Try receiving message from a mailbox that has been stopped, expect error MAILBOX_STOPPED (1003)\n");

	printf("Sending Message to myself.\n");
	ret = SendMsg(mypid, mesg, 15, false);
	if (ret){
	  printf("Send failed: error = %d, mypid = %d", ret, mypid);
	}
	int msgCount;
	//now stop mailbox
	ManageMailbox(true, &msgCount);
	printf("Mailbox stopped.\n");
        ret = RcvMsg(&sender,msg,&len,false);
	printf("Try recieve message\n");
	printf("Should recieve message from non-empty stopped mailbox\n");
	if (ret){
		printf("Receive failed! error = %d\n", ret);
	}
        else{
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);	
	}
	ret = RcvMsg(&sender,msg,&len,false);
	printf("Try recieve message again\n");
	printf("Should not recieve message from empty stopped mailbox\n");
	if (ret) {
		printf("Receive failed! error = %d\n", ret);
		count++;
	}
        else{
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	}

	/*******************************test6************************************/
	printf("###TEST6###\n");
	printf("Try sending message to a mailbox that has been stopped, expect error MAILBOX_STOPPED (1003)\n");
	printf("Now try send message to myself again, my mailbox is stopped so should get error\n");
	ret = SendMsg(mypid, mesg, 15, false);
	if (ret){
		printf("Send failed: error = %d, mypid = %d\n", ret, mypid);
		if (ret == MAILBOX_STOPPED) count++;
	}
	else{
		printf("Message Sent.\n");
		count--;
	}

	/*******************************test7************************************/
	printf("###TEST7###\n");
	printf("Try sending a message to myself with negative length, expect error MSG_LENGTH_ERROR (1005)\n");
	ret = SendMsg(mypid, mesg, -3, false);
	if (ret) {
		printf("Send failed: error = %d, mypid = %d\n", ret, mypid);
		if (ret == MSG_LENGTH_ERROR) count++;
	}
	else {
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);	
		count--;
	}

	/*******************************test8************************************/
	printf("###TEST8###\n");
	printf("Try sending a message to myself with length greater than max, expect error MSG_LENGTH_ERROR (1005)\n");
	ret = SendMsg(mypid, mesg, 200, false);
	if (ret) {
		printf("Send failed: error = %d, mypid = %d\n", ret, mypid);
		if (ret == MSG_LENGTH_ERROR) count++;
	}
	else {
		printf("Message received.\n");
		printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);	
		count--;
	}

	/*******************************test9************************************
	printf("###TEST9###\n");
	printf("Try sending a message to myself with \n");

/*
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
*/
	
	/*
	void *msg[128];
    int len;
    bool block = true;
	int sender;
    ret = RcvMsg(&sender,msg,&len,block);
    printf("Message received.\n");
    printf("Message: %s, sender = %d, len = %d, mypid = %d return = %d\n", (char *) msg, sender, len, mypid, ret);
	*/
	printf("%d/8 tests passed\n", count);
	return 0;
}


