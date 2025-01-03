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
#include <unistd.h>

//#include "bpf_util.h"
//#include "trace_helpers.h"

#define __NR_hello 463

extern char **environ;

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	//char filename[256];
	//snprintf(filename, sizeof(filename), "%s.kern.o", argv[0]);
	char *filename = "long_running1.kern.o";
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed : %s\n", strerror(libbpf_get_error(obj)));
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "tracepoint_exit_saterm_connect1");
	if (!prog) {
		fprintf(stderr, "ERROR: fiding a prog in obj file failed\n");
		goto cleanup;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	int my_map = bpf_object__find_map_fd_by_name(obj, "my_map");
	if (my_map < 0) {
		fprintf(stderr, "ERROR: finding map in obj file failed\n");
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

	//syscall(__NR_hello);
	pid_t pid;
	char *argv_new[] = {"./saterm.test", "15", (char *)NULL};
	
	printf("e 1\n");
	posix_spawn(&pid, "./saterm.test", NULL, NULL, argv_new, environ);
	printf("e 2\n");

	sleep(3);
	printf("e 3\n");
	system("bpftool prog terminate `bpftool prog show | awk 'NR==1 {gsub(\":\", \"\", $1); print $1}'`");
	printf("e 4\n");
	waitpid(pid, NULL, 0);
	printf("e 5\n");

	bpf_link__disconnect(link);
	//read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
