ifndef RELIC_LOC
$(error Source the source_me file first for the RELIC environment variables!)
endif

CFLAGS  ?= -I$(RELIC_LOC)/include -lrelic 
# CFLAGS  += -fno-omit-frame-pointer -g -Wall -march=native -o2
LDFLAGS ?= -L$(RELIC_LOC)/lib

all: clean test

test: pre.c fpga.c csp.c ttp.c developer.c test.c
	gcc $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f test
