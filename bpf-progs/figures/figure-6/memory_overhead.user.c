/*
 * User-space program to measure runtime memory overhead of eBPF programs
 * that allocate objects with bpf_obj_new.
 *
 * Usage:
 *   ./memory_overhead.user <max_objects> <num_runs> <kernel_label> [output_csv]
 *
 * The program increments object count from 1..max_objects, triggers the BPF
 * program to allocate objects, and records memory deltas and BPF prog sizes.
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#define __NR_saterm_test 470

struct control_args {
	__u32 target_objects;
	__u32 cleanup;
};

struct stats {
	__u32 allocated;
	__u32 failed;
	__u32 dropped;
};

static volatile bool keep_running = true;

static void signal_handler(int signo)
{
	(void)signo;
	keep_running = false;
}

static void trigger_tracepoint(void)
{
	syscall(__NR_saterm_test);
}

static int read_meminfo_kb(const char *key, long *out)
{
	FILE *fp = fopen("/proc/meminfo", "r");
	char line[256];
	size_t key_len;

	if (!fp)
		return -1;

	key_len = strlen(key);
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, key, key_len) == 0 && line[key_len] == ':') {
			long value = 0;
			if (sscanf(line + key_len + 1, "%ld", &value) == 1) {
				*out = value;
				fclose(fp);
				return 0;
			}
		}
	}

	fclose(fp);
	return -1;
}

static int get_prog_sizes(int prog_fd, __u32 *xlated_len, __u32 *jited_len)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return -1;

	*xlated_len = info.xlated_prog_len;
	*jited_len = info.jited_prog_len;
	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <max_objects> <num_runs> <kernel_label> [output_csv]\n", prog);
	fprintf(stderr, "Example: %s 128 5 saterm results.csv\n", prog);
}

int main(int argc, char **argv)
{
	const char *csv_filename = "results.csv";
	const char *kernel_label;
	int max_objects;
	int num_runs;
	FILE *csv = NULL;

	if (argc < 4) {
		print_usage(argv[0]);
		return 1;
	}

	max_objects = atoi(argv[1]);
	num_runs = atoi(argv[2]);
	kernel_label = argv[3];
	if (argc >= 5)
		csv_filename = argv[4];

	if (max_objects <= 0 || num_runs <= 0) {
		fprintf(stderr, "ERROR: max_objects and num_runs must be > 0\n");
		return 1;
	}

	csv = fopen(csv_filename, "w");
	if (!csv) {
		perror("ERROR: opening CSV file");
		return 1;
	}

	fprintf(csv,
		"kernel_type,num_objects,run,allocated_objects,failed_allocations,"
		"mem_avail_before_kb,mem_avail_after_load_kb,mem_avail_after_alloc_kb,"
		"mem_free_before_kb,mem_free_after_load_kb,mem_free_after_alloc_kb,"
		"xlated_prog_len,jited_prog_len\n");
	fflush(csv);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	for (int target = 1; target <= max_objects && keep_running; target++) {
		bool reached_limit = false;

		for (int run = 0; run < num_runs && keep_running; run++) {
			struct bpf_object *obj = NULL;
			struct bpf_program *prog = NULL;
			struct bpf_link *link = NULL;
			int control_fd = -1;
			int stats_fd = -1;
			int prog_fd = -1;
			struct control_args ctl = {};
			struct stats st = {};
			__u32 key = 0;
			long mem_avail_before = 0;
			long mem_avail_after_load = 0;
			long mem_avail_after_alloc = 0;
			long mem_free_before = 0;
			long mem_free_after_load = 0;
			long mem_free_after_alloc = 0;
			__u32 xlated_len = 0;
			__u32 jited_len = 0;

			if (read_meminfo_kb("MemAvailable", &mem_avail_before) != 0 ||
			    read_meminfo_kb("MemFree", &mem_free_before) != 0) {
				fprintf(stderr, "WARN: failed reading /proc/meminfo\n");
			}

			obj = bpf_object__open_file("memory_overhead.kern.o", NULL);
			if (libbpf_get_error(obj)) {
				fprintf(stderr, "ERROR: opening BPF object failed: %s\n",
					strerror(libbpf_get_error(obj)));
				goto run_cleanup;
			}

			if (bpf_object__load(obj)) {
				fprintf(stderr, "ERROR: loading BPF object failed\n");
				goto run_cleanup;
			}

			if (read_meminfo_kb("MemAvailable", &mem_avail_after_load) != 0 ||
			    read_meminfo_kb("MemFree", &mem_free_after_load) != 0) {
				fprintf(stderr, "WARN: failed reading /proc/meminfo after load\n");
			}

			prog = bpf_object__find_program_by_name(obj,
				"tracepoint_exit_memory_overhead");
			if (!prog) {
				fprintf(stderr, "ERROR: finding BPF program failed\n");
				goto run_cleanup;
			}

			prog_fd = bpf_program__fd(prog);
			if (prog_fd < 0) {
				fprintf(stderr, "ERROR: getting program fd failed\n");
				goto run_cleanup;
			}

			if (get_prog_sizes(prog_fd, &xlated_len, &jited_len) != 0) {
				fprintf(stderr, "WARN: failed to read program sizes\n");
			}

			link = bpf_program__attach(prog);
			if (libbpf_get_error(link)) {
				fprintf(stderr, "ERROR: attaching program failed: %ld\n",
					libbpf_get_error(link));
				link = NULL;
				goto run_cleanup;
			}

			control_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
			stats_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
			if (control_fd < 0 || stats_fd < 0) {
				fprintf(stderr, "ERROR: finding maps failed\n");
				goto run_cleanup;
			}

			memset(&st, 0, sizeof(st));
			if (bpf_map_update_elem(stats_fd, &key, &st, BPF_ANY) != 0) {
				fprintf(stderr, "ERROR: resetting stats failed\n");
				goto run_cleanup;
			}

			ctl.cleanup = 1;
			ctl.target_objects = 0;
			if (bpf_map_update_elem(control_fd, &key, &ctl, BPF_ANY) != 0) {
				fprintf(stderr, "ERROR: setting cleanup control failed\n");
				goto run_cleanup;
			}
			trigger_tracepoint();

			ctl.cleanup = 0;
			ctl.target_objects = target;
			if (bpf_map_update_elem(control_fd, &key, &ctl, BPF_ANY) != 0) {
				fprintf(stderr, "ERROR: setting target control failed\n");
				goto run_cleanup;
			}
			trigger_tracepoint();

			if (bpf_map_lookup_elem(stats_fd, &key, &st) != 0) {
				fprintf(stderr, "ERROR: reading stats failed\n");
				goto run_cleanup;
			}

			if (read_meminfo_kb("MemAvailable", &mem_avail_after_alloc) != 0 ||
			    read_meminfo_kb("MemFree", &mem_free_after_alloc) != 0) {
				fprintf(stderr, "WARN: failed reading /proc/meminfo after alloc\n");
			}

			fprintf(csv,
				"%s,%d,%d,%u,%u,%ld,%ld,%ld,%ld,%ld,%ld,%u,%u\n",
				kernel_label, target, run,
				st.allocated, st.failed,
				mem_avail_before, mem_avail_after_load, mem_avail_after_alloc,
				mem_free_before, mem_free_after_load, mem_free_after_alloc,
				xlated_len, jited_len);
			fflush(csv);

			if (st.allocated < (unsigned int)target)
				reached_limit = true;

run_cleanup:
			if (control_fd >= 0) {
				ctl.cleanup = 1;
				ctl.target_objects = 0;
				bpf_map_update_elem(control_fd, &key, &ctl, BPF_ANY);
				trigger_tracepoint();
			}
			if (link)
				bpf_link__destroy(link);
			if (obj)
				bpf_object__close(obj);

			if (reached_limit)
				break;
		}

		if (reached_limit)
			break;
	}

	fclose(csv);
	printf("Results written to %s\n", csv_filename);
	return 0;
}
