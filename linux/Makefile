CC=gcc
LD=ld
CFLAGS=-O0 -fpie -Wall -fshort-wchar --std=c11
MAKE=make

TARGETS = fwup

.SUFFIXES:

all : $(TARGETS)

% : %.o
	$(CC) $(CFLAGS) -o $@ $^ -lefivar

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean :
	@rm -vf $(TARGETS) *.o *.so
