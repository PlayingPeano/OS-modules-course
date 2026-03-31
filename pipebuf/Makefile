obj-m += pipebuf.o

all: modules test_pipebuf

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test_pipebuf: test_pipebuf.c pipebuf_ioctl.h
	gcc -Wall -o test_pipebuf test_pipebuf.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f test_pipebuf
