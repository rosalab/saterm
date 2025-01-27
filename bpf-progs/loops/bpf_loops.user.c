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
#include <sys/wait.h>

//#include "bpf_util.h"
//#include "trace_helpers.h"

extern char **environ;

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;

//	char *filename = "bpf_loops.kern.o";
    char *filename= "long_running1.kern.o";
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed : %s\n", strerror(libbpf_get_error(obj)));
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "tracepoint_exit_saterm");
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

	pid_t pid;
	char *argv_new[] = {"./trigger", (char *)NULL};
	posix_spawn(&pid, "./trigger", NULL, NULL, argv_new, environ);
	waitpid(pid, NULL, 0);

	while(1);

	bpf_link__disconnect(link);

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
