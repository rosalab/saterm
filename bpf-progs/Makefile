SOURCES := $(wildcard *.kern.c)
FILES := $(SOURCES:.c=.o)
MAP_FINE_SRC := $(wildcard map-fine/*.kern.c)
MAP_FINE_OBJ := $(MAP_FINE_SRC:.c=.o)
MAP_FINE_USER_SRC := $(wildcard map-fine/*.user.c)
MAP_FINE_USER_OBJ := $(MAP_FINE_USER_SRC:.c=)
USER_SRC := $(wildcard *.user.c)
USER := $(USER_SRC:.c=)
BPF-CLANG := clang
BPF_CLANG_CFLAGS := -target bpf -g -Wall -O2 -c
INCLUDE := -I../linux/usr/include/ -I../linux/tools/lib/
USER-CFLAGS := -g -I../linux/usr/include -I../linux/tools/lib/ -L../linux/tools/lib/bpf/


all: $(FILES) $(USER) saterm.test test_syscall verify_bpf_throw

test: test.c
	$(BPF-CLANG) $(INCLUDE) $(BPF_CLANG_CFLAGS) -o test test.c

saterm.test: saterm.test.c
	gcc $(USER-CFLAGS) $< -o $@

test_syscall: test_syscall.c
	gcc $(USER-CFLAGS) $< -o $@

verify_bpf_throw: verify_bpf_throw.c
	gcc $(USER-CFLAGS) $< -lbpf -o $@

$(FILES) : %.o : %.c
	$(BPF-CLANG) $(INCLUDE) $(BPF_CLANG_CFLAGS) -o $@ $<

$(USER) : % : %.c
	gcc $(USER-CFLAGS) $< -lbpf -o $@

.PHONY : clean

clean :
	rm -f $(FILES) $(USER) saterm.test test_syscall verify_bpf_throw
