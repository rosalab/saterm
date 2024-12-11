#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

//#include "bpf_util.h"
//#include "trace_helpers.h"

#define __NR_hello 463

extern char **environ;

int handle_helper_case();
void recursively_handle(int iters);

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char *filename = "max_insts.kern.o";
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed : %s\n", strerror(libbpf_get_error(obj)));
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "tracepoint_exit_saterm_connect3");
	if (!prog) {
		fprintf(stderr, "ERROR: fiding a prog in obj file failed\n");
		goto cleanup;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}


	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed : %ld\n", libbpf_get_error(link));
		link = NULL;
		goto cleanup;
	} else {
		printf("Attach success\n");
	}

	for (int i = 0; i < 10; i++){
		syscall(__NR_hello);
		usleep(1000);
	}

	bpf_link__disconnect(link);
	//read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);

	recursively_handle(100000); // capped out
	handle_helper_case();
}

void recursively_handle(int iters) {
	if (iters == 0) handle_helper_case();
	recursively_handle(iters - 1);
	volatile i = 1;
}

int handle_helper_case() {
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char *filename = "single_get_stackid.kern.o";
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed : %s\n", strerror(libbpf_get_error(obj)));
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "tracepoint_exit_saterm_connect4");
	if (!prog) {
		fprintf(stderr, "ERROR: fiding a prog in obj file failed\n");
		goto cleanup2;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup2;
	}


	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed : %ld\n", libbpf_get_error(link));
		link = NULL;
		goto cleanup2;
	} else {
		printf("Attach success\n");
	}

	for (int i = 0; i < 10; i++){
		syscall(__NR_hello);
		usleep(1000);
	}

	bpf_link__disconnect(link);
	//read_trace_pipe();

cleanup2:
	bpf_link__destroy(link);
	bpf_object__close(obj);

	exit(0);
}

