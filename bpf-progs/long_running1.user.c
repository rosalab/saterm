#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <spawn.h>
#include <stdbool.h>
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
	// 1. Spawn throughput tester
	pid_t pid;
	char *argv_new[] = {"./saterm.test", "30", (char *)NULL};
	posix_spawn(&pid, "./saterm.test", NULL, NULL, argv_new, environ);

	// 2. Sleep 4 sec
	sleep(4);

	// 3. Attach eBPF program
	char *bpf_program = argv[1];
	bool should_terminate = argv[2] ? (strcmp(argv[2], "term") == 0) : true;

	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	obj = bpf_object__open_file(bpf_program, NULL);
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

	// 4. Sleep 9 sec
	sleep(9);

	// 5. Either terminate or delink eBPF program
	if (should_terminate) {
		system("bpftool prog terminate `bpftool prog show | awk 'NR==1 {gsub(\":\", \"\", $1); print $1}'`");
		// This frees remaining memory (otherwise refcount is not decremented)
		bpf_link__disconnect(link);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		exit(0);
	} else {
		// Delinking through these functions doesn't seem to fully work
		// But exiting seems to cause a delinking
		// Yes it makes a zombie process, blah blah best practice, not important

		//printf("About to delink!\n");
		bpf_link__disconnect(link);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		exit(0);
	}

	waitpid(pid, NULL, 0);


	if (!should_terminate) return 0;
	
	bpf_link__disconnect(link);
	//read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
