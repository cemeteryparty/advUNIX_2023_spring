
CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g

ASM64	= yasm -f elf64 -DYASM -D__x86_64__
#ASM64	= nasm -f elf64 -DNASM -D__x86_64__

PROGS	= sdb

all: $(PROGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

sdb: sdb.o ptools.o elf_parser.o
	${CXX} $^ -lcapstone -o $@

setuid: shadow
	sudo chown root:root shadow
	sudo chmod 4755 shadow

clean:
	rm -f *.o *~ $(PROGS)
