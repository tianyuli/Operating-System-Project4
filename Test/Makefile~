#author: Xi Wen(xwen), Tianyu Li(tli), Xia Li(xli2)

all: test1 test2 test3

mailbox.o: mailbox.c mailbox.h
	gcc -Wall -c mailbox.c

test1: test1.o mailbox.o
	gcc -Wall -g test1.o mailbox.o -o test1

test1.o: test1.c mailbox.h
	gcc -Wall -g -c test1.c 

test2: test2.o mailbox.o
	gcc -Wall -g test2.o mailbox.o -o test2

test2.o: test2.c mailbox.h
	gcc -Wall -g -c test2.c 

test3: test3.o mailbox.o
	gcc -Wall -g test3.o mailbox.o -o test3

test3.o: test3.c mailbox.h
	gcc -Wall -g -c test3.c 

clean:
	rm *.o test1 test2 test3
