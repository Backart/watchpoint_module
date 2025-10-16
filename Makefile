obj-m := watchpoint_module.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

TEST_SRC := test/test_watchpoint.c
TEST_BIN := test/test_watchpoint

all: module test

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

test: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) -Wall -O2 -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(TEST_BIN)
