
CC		= gcc
CPP     = g++
FLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
CFLAGS  = -shared -fPIC -ldl
CFLAGSA = -shared -fPIE -no-pie -ldl
LDFLAGS = -lunwind -lunwind-$(shell uname -m)
PROGS	= sandbox.so

all: $(PROGS)

sandbox.so: sandbox.c
	$(CC) -o $@ $(CFLAGS) $^ 

adv: sandbox.cpp
	$(CPP) -o $(PROGS) -shared -fPIC sandbox.cpp -ldl

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__
	rm -rf *.html*
	rm -rf *.log

