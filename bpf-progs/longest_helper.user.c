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
	obj = bpf_object__open_file("get_stackid_pure.kern.o", NULL);
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

	recursively_handle(200000);
	//recursively_handle(1);
	//handle_helper_case();

	bpf_link__disconnect(link);
	//read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
}

void recursively_handle(int iters) {
	if (iters == 0) handle_helper_case();
	recursively_handle(iters - 1);
}

int handle_helper_case() {
	for (int i = 0; i < 20; i++){
		syscall(__NR_hello);
		// removing the extra pause seems to help for consistency
		//usleep(1000);
	}
	exit(0);
}

