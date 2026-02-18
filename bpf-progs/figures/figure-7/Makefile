SOURCES := $(wildcard *.kern.c)
FILES := $(SOURCES:.c=.o)
USER_SRC := $(wildcard *.user.c)
USER := $(USER_SRC:.c=)
BPF-CLANG := clang
BPF_CLANG_CFLAGS := -target bpf -g -Wall -O2 -c -D__TARGET_ARCH_x86
EXTRA_CFLAGS ?=
INCLUDE := -I../../../linux/usr/include/ -I../../../linux/tools/lib/
USER-CFLAGS := -g -I../../../linux/tools/lib/ -L../../../linux/tools/lib/bpf/ -Wl,-rpath,../../../linux/tools/lib/bpf/

all: $(FILES) $(USER)

$(FILES): %.o : %.c
	$(BPF-CLANG) $(INCLUDE) $(BPF_CLANG_CFLAGS) $(EXTRA_CFLAGS) -o $@ $<

$(USER): % : %.c
	gcc $(USER-CFLAGS) $< -lbpf -o $@

.PHONY: clean
clean:
	rm -f $(FILES) $(USER)
