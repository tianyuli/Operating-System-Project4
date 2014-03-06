#author: Xi Wen(xwen), Tianyu Li(tli), Xia Li(xli2)

all: test1 test2 test3 test4 test5

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

test4: test4.o mailbox.o
	gcc -Wall -g test4.o mailbox.o -o test4

test4.o: test4.c mailbox.h
	gcc -Wall -g -c test4.c 

test5: test5.o mailbox.o
	gcc -Wall -g test5.o mailbox.o -o test5

test5.o: test5.c mailbox.h
	gcc -Wall -g -c test5.c 

clean:
	rm *.o test1 test2 test3 test4 test5
