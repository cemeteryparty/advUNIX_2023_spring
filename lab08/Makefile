
CC		= gcc
CFLAGS	= -static-pie
PROGS	= solver

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

solver: solver.c
	$(CC) -o $@ $^ $(CFLAGS)

test:
	./solver ./sample1
	./solver ./sample2
	./solver ./sample3

clean:
	rm -f $(PROGS) *.o
