/*
 * Figure-8 benchmark runner.
 *
 * Runs three sweeps:
 * 1) Verification time vs number of branches (times bpftool prog load)
 * 2) Termination time vs number of local objects
 *    - kflex: uses /proc/bpf_throw_stats for accurate bpf_throw timing
 *    - saterm: uses run_time_ns delta from bpf_prog_info
 * 3) Load-time memory vs number of local objects (MemAvailable delta)
 *
 * Use tag "baseline" for unmodified kernel: runs memory sweep only.
 * Run baseline manually on vanilla kernel and merge baseline_memory.csv
 * into your results.
 *
 * Usage:
 *   ./figure8.user <saterm|kflex|baseline> <num_branches> <num_objects>
 *                  <iteration_interval> <num_runs>
 *                  [branches_csv] [objects_csv] [memory_csv] [--verbose]
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define __NR_saterm_test 470
#define BPFTOOL_BIN "/home/rosa/saterm/linux/tools/bpf/bpftool/bpftool"
#define BPF_THROW_STATS_PATH "/proc/bpf_throw_stats"

struct bpf_throw_stats_read {
	uint64_t total_time_ns;
	uint64_t stack_walk_time_ns;
	uint64_t call_count;
};

struct kernel_variant {
	const char *tag;
	const char *branches_obj;   /* NULL for baseline */
	const char *objects_obj;    /* for termination; NULL for baseline */
	const char *memory_obj;    /* for load-time memory sweep */
	bool branches_and_objects; /* false for baseline: memory only */
};

static uint64_t get_program_runtime_ns(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return 0;
	return info.run_time_ns;
}

static int run_make_compile(const char *object_file, const char *macro_name, int value)
{
	char cmd[512];
	int rc;

	rc = snprintf(cmd, sizeof(cmd),
		      "make -s -B %s EXTRA_CFLAGS=\"-D%s=%d\"",
		      object_file, macro_name, value);
	if (rc <= 0 || rc >= (int)sizeof(cmd)) {
		fprintf(stderr, "ERROR: make command too long\n");
		return -1;
	}

	rc = system(cmd);
	if (rc != 0) {
		fprintf(stderr, "ERROR: command failed: %s\n", cmd);
		return -1;
	}
	return 0;
}

static int run_command(const char *cmd)
{
	int rc = system(cmd);

	if (rc != 0) {
		fprintf(stderr, "ERROR: command failed: %s\n", cmd);
		return -1;
	}
	return 0;
}

static void run_command_ignore_fail(const char *cmd)
{
	(void)system(cmd);
}

static int reset_bpf_throw_stats(void)
{
	FILE *fp = fopen(BPF_THROW_STATS_PATH, "w");

	if (!fp)
		return -1;
	if (fprintf(fp, "reset") < 0) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

static int read_bpf_throw_stats(struct bpf_throw_stats_read *out)
{
	FILE *fp;
	char line[256];
	uint64_t total_calls = 0, total_time = 0, avg_stack_walk_ns = 0;

	memset(out, 0, sizeof(*out));
	fp = fopen(BPF_THROW_STATS_PATH, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "  Total calls:           %llu", (unsigned long long *)&total_calls) == 1)
			continue;
		if (sscanf(line, "  Total time:            %llu ns", (unsigned long long *)&total_time) == 1)
			continue;
		if (sscanf(line, "  Avg stack walk time:   %llu ns", (unsigned long long *)&avg_stack_walk_ns) == 1)
			continue;
	}
	fclose(fp);

	if (total_calls == 0)
		return -1;

	out->call_count = total_calls;
	out->total_time_ns = total_time;
	out->stack_walk_time_ns = avg_stack_walk_ns; /* already per-call average */
	return 0;
}

static bool bpf_throw_proc_available(void)
{
	return access(BPF_THROW_STATS_PATH, R_OK | W_OK) == 0;
}

static int run_bpftool_load_and_parse_verify_ns(const char *cmd, uint64_t *verify_ns_out,
						bool verbose)
{
	FILE *pipe = NULL;
	char line[1024];
	char output_buf[8192];
	size_t output_len = 0;
	unsigned long long verify_usec = 0;
	int found = 0;
	int status;

	pipe = popen(cmd, "r");
	if (!pipe) {
		fprintf(stderr, "ERROR: popen failed for command: %s\n", cmd);
		return -1;
	}

	while (fgets(line, sizeof(line), pipe)) {
		char *p = strstr(line, "verification time ");
		unsigned long long parsed_usec = 0;

		if (output_len + strlen(line) + 1 < sizeof(output_buf)) {
			strcpy(&output_buf[output_len], line);
			output_len += strlen(line);
		}

		if (!p)
			continue;
		/*
		 * Accept the normal verifier form:
		 *   "verification time 524 usec"
		 * and tolerate extra spacing before "usec".
		 */
		if (sscanf(p, "verification time %llu usec", &parsed_usec) == 1 ||
		    sscanf(p, "verification time %llu  usec", &parsed_usec) == 1) {
			verify_usec = parsed_usec;
			found = 1;
		}
	}

	if (output_len == 0)
		output_buf[0] = '\0';

	status = pclose(pipe);
	if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "ERROR: command failed: %s\n", cmd);
		if (output_buf[0] != '\0')
			fprintf(stderr, "%s", output_buf);
		return -1;
	}
	if (verbose && output_buf[0] != '\0')
		fprintf(stderr, "%s", output_buf);

	if (found) {
		*verify_ns_out = (uint64_t)verify_usec * 1000ULL;
		return 0;
	}
	if (output_buf[0] != '\0')
		fprintf(stderr, "DEBUG: bpftool output (no verifier timing line):\n%s", output_buf);
	return 1;
}

static int measure_verification_time_ns(const char *kern_o, uint64_t *verify_ns_out,
					bool verbose)
{
	char pin_path[256];
	char load_cmd[1024];
	char unlink_cmd[512];
	struct timespec now = {};
	int ret = -1;
	int rc;

	if (access(BPFTOOL_BIN, X_OK) != 0) {
		fprintf(stderr, "ERROR: bpftool not executable at %s: %s\n",
			BPFTOOL_BIN, strerror(errno));
		return -1;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		fprintf(stderr, "ERROR: clock_gettime failed for pin naming: %s\n", strerror(errno));
		return -1;
	}

	rc = snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/figure8_verify_%d_%lld_%ld",
		      getpid(), (long long)now.tv_sec, now.tv_nsec);
	if (rc <= 0 || rc >= (int)sizeof(pin_path)) {
		fprintf(stderr, "ERROR: pin path too long\n");
		return -1;
	}

	rc = snprintf(load_cmd, sizeof(load_cmd),
		      "%s -d prog load %s %s 2>&1",
		      BPFTOOL_BIN, kern_o, pin_path);
	if (rc <= 0 || rc >= (int)sizeof(load_cmd)) {
		fprintf(stderr, "ERROR: load command too long\n");
		return -1;
	}

	rc = snprintf(unlink_cmd, sizeof(unlink_cmd), "rm -f %s", pin_path);
	if (rc <= 0 || rc >= (int)sizeof(unlink_cmd)) {
		fprintf(stderr, "ERROR: cleanup command too long\n");
		return -1;
	}

	rc = run_bpftool_load_and_parse_verify_ns(load_cmd, verify_ns_out, verbose);
	if (rc < 0)
		goto cleanup;
	if (rc == 0) {
		ret = 0;
		goto cleanup;
	}

	fprintf(stderr,
		"ERROR: bpftool output did not include 'verification time ... usec' for %s\n",
		kern_o);
	ret = -1;

cleanup:
	/* Unpinning closes the pinned reference and lets kernel release program. */
	run_command_ignore_fail(unlink_cmd);
	return ret;
}

static int measure_termination_time_ns(const char *kern_o, const char *kernel_tag,
				      uint64_t *term_ns_out, uint64_t *stack_walk_ns_out)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL;
	uint64_t runtime_before = 0;
	uint64_t runtime_after = 0;
	struct bpf_throw_stats_read proc_stats;
	bool use_proc = false;
	int prog_fd;
	int ret = -1;

	if (stack_walk_ns_out)
		*stack_walk_ns_out = 0;

	if (kernel_tag && strcmp(kernel_tag, "kflex") == 0 && bpf_throw_proc_available()) {
		use_proc = true;
		if (reset_bpf_throw_stats() != 0)
			use_proc = false;
	}

	obj = bpf_object__open_file(kern_o, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening %s failed: %ld\n", kern_o, libbpf_get_error(obj));
		return -1;
	}

	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "ERROR: loading %s failed\n", kern_o);
		goto out;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		fprintf(stderr, "ERROR: no program found in %s\n", kern_o);
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: invalid program fd for %s\n", kern_o);
		goto out;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: attach failed for %s: %ld\n", kern_o, libbpf_get_error(link));
		link = NULL;
		goto out;
	}

	runtime_before = get_program_runtime_ns(prog_fd);
	syscall(__NR_saterm_test);
	runtime_after = get_program_runtime_ns(prog_fd);

	if (use_proc && read_bpf_throw_stats(&proc_stats) == 0 && proc_stats.call_count > 0) {
		*term_ns_out = proc_stats.total_time_ns / proc_stats.call_count;
		if (stack_walk_ns_out)
			*stack_walk_ns_out = proc_stats.stack_walk_time_ns; /* already per-call avg */
	} else {
		*term_ns_out = runtime_after - runtime_before;
	}

	ret = 0;

out:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	return ret;
}

static int run_branch_sweep(const char *kernel_tag, const char *branch_obj, int max_branches,
			    int step, int num_runs, FILE *csv, bool verbose)
{
	int branches;

	for (branches = 0; branches <= max_branches; branches += step) {
		int run;

		if (run_make_compile(branch_obj, "MAX_BRANCHES", branches) != 0)
			return -1;

		for (run = 1; run <= num_runs; run++) {
			uint64_t verify_ns = 0;

			if (measure_verification_time_ns(branch_obj, &verify_ns, verbose) != 0) {
				fprintf(stderr, "ERROR: branch sweep failed at branches=%d run=%d\n",
					branches, run);
				return -1;
			}

			fprintf(csv, "%s,%d,%d,%llu\n",
				kernel_tag, branches, run, (unsigned long long)verify_ns);
		}
		fflush(csv);
	}

	return 0;
}

static int run_object_sweep(const char *kernel_tag, const char *object_obj, int max_objects,
			    int step, int num_runs, FILE *csv, bool use_proc_stats)
{
	int objects;

	for (objects = 0; objects <= max_objects; objects += step) {
		int run;

		if (run_make_compile(object_obj, "MAX_LOCAL_OBJS", objects) != 0)
			return -1;

		for (run = 1; run <= num_runs; run++) {
			uint64_t term_ns = 0;
			uint64_t stack_walk_ns = 0;

			if (measure_termination_time_ns(object_obj, kernel_tag,
							&term_ns, use_proc_stats ? &stack_walk_ns : NULL) != 0) {
				fprintf(stderr, "ERROR: object sweep failed at objects=%d run=%d\n",
					objects, run);
				return -1;
			}

			if (use_proc_stats)
				fprintf(csv, "%s,%d,%d,%llu,%llu\n",
					kernel_tag, objects, run,
					(unsigned long long)term_ns,
					(unsigned long long)stack_walk_ns);
			else
				fprintf(csv, "%s,%d,%d,%llu\n",
					kernel_tag, objects, run, (unsigned long long)term_ns);
		}
		fflush(csv);
	}

	return 0;
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

static int measure_load_memory_kb(const char *kern_o, long *mem_avail_before, long *mem_avail_after,
				 long *mem_free_before, long *mem_free_after,
				 __u32 *xlated_len, __u32 *jited_len)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	int prog_fd;
	int ret = -1;

	*xlated_len = 0;
	*jited_len = 0;

	if (read_meminfo_kb("MemAvailable", mem_avail_before) != 0 ||
	    read_meminfo_kb("MemFree", mem_free_before) != 0) {
		fprintf(stderr, "ERROR: failed reading /proc/meminfo before load\n");
		return -1;
	}

	obj = bpf_object__open_file(kern_o, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening %s failed: %ld\n", kern_o, libbpf_get_error(obj));
		return -1;
	}

	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "ERROR: loading %s failed\n", kern_o);
		goto out;
	}

	if (read_meminfo_kb("MemAvailable", mem_avail_after) != 0 ||
	    read_meminfo_kb("MemFree", mem_free_after) != 0) {
		fprintf(stderr, "ERROR: failed reading /proc/meminfo after load\n");
		goto out;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (prog) {
		prog_fd = bpf_program__fd(prog);
		if (prog_fd >= 0) {
			struct bpf_prog_info info = {};
			__u32 info_len = sizeof(info);

			if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
				*xlated_len = info.xlated_prog_len;
				*jited_len = info.jited_prog_len;
			}
		}
	}

	ret = 0;

out:
	if (obj)
		bpf_object__close(obj);
	return ret;
}

static int run_memory_sweep(const char *kernel_tag, const char *memory_obj, int max_objects,
			    int step, int num_runs, FILE *csv)
{
	int objects;

	for (objects = 0; objects <= max_objects; objects += step) {
		int run;

		if (run_make_compile(memory_obj, "MAX_LOCAL_OBJS", objects) != 0)
			return -1;

		for (run = 1; run <= num_runs; run++) {
			long mem_avail_before = 0, mem_avail_after = 0;
			long mem_free_before = 0, mem_free_after = 0;
			__u32 xlated_len = 0, jited_len = 0;

			if (measure_load_memory_kb(memory_obj,
						  &mem_avail_before, &mem_avail_after,
						  &mem_free_before, &mem_free_after,
						  &xlated_len, &jited_len) != 0) {
				fprintf(stderr, "ERROR: memory sweep failed at objects=%d run=%d\n",
					objects, run);
				return -1;
			}

			fprintf(csv, "%s,%d,%d,%ld,%ld,%ld,%ld,%u,%u\n",
				kernel_tag, objects, run,
				mem_avail_before, mem_avail_after,
				mem_free_before, mem_free_after,
				xlated_len, jited_len);
		}
		fflush(csv);
	}

	return 0;
}

int main(int argc, char **argv)
{
	const struct kernel_variant variants[] = {
		{
			.tag = "saterm",
			.branches_obj = "branches_die.kern.o",
			.objects_obj = "objects_die.kern.o",
			.memory_obj = "objects_die.kern.o",
			.branches_and_objects = true,
		},
		{
			.tag = "kflex",
			.branches_obj = "branches_throw.kern.o",
			.objects_obj = "objects_throw.kern.o",
			.memory_obj = "objects_throw.kern.o",
			.branches_and_objects = true,
		},
		{
			.tag = "baseline",
			.branches_obj = NULL,
			.objects_obj = NULL,
			.memory_obj = "objects_baseline.kern.o",
			.branches_and_objects = false,
		},
	};
	const struct kernel_variant *selected = NULL;
	const char *kernel_tag;
	const char *branches_csv_path;
	const char *objects_csv_path;
	const char *memory_csv_path;
	bool verbose = false;
	bool branches_set = false;
	bool objects_set = false;
	bool memory_set = false;
	char default_branches_csv[128];
	char default_objects_csv[128];
	char default_memory_csv[128];
	FILE *branches_csv = NULL;
	FILE *objects_csv = NULL;
	FILE *memory_csv = NULL;
	int stats_fd = -1;
	int max_branches;
	int max_objects;
	int step;
	int num_runs;
	size_t i;
	int rc = 1;

	if (argc < 6) {
		fprintf(stderr,
			"Usage: %s <saterm|kflex|baseline> <num_branches> <num_objects> "
			"<iteration_interval> <num_runs> [branches_csv] [objects_csv] [memory_csv] [--verbose]\n",
			argv[0]);
		return 1;
	}

	kernel_tag = argv[1];
	max_branches = atoi(argv[2]);
	max_objects = atoi(argv[3]);
	step = atoi(argv[4]);
	num_runs = atoi(argv[5]);

	if (max_branches < 0 || max_objects < 0 || step <= 0 || num_runs <= 0) {
		fprintf(stderr, "ERROR: invalid numeric arguments\n");
		return 1;
	}

	for (i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
		if (strcmp(kernel_tag, variants[i].tag) == 0) {
			selected = &variants[i];
			break;
		}
	}
	if (!selected) {
		fprintf(stderr, "ERROR: kernel tag must be 'saterm', 'kflex', or 'baseline'\n");
		return 1;
	}

	snprintf(default_branches_csv, sizeof(default_branches_csv), "%s_branches.csv", kernel_tag);
	snprintf(default_objects_csv, sizeof(default_objects_csv), "%s_objects.csv", kernel_tag);
	snprintf(default_memory_csv, sizeof(default_memory_csv), "%s_memory.csv", kernel_tag);
	branches_csv_path = default_branches_csv;
	objects_csv_path = default_objects_csv;
	memory_csv_path = default_memory_csv;

	for (i = 6; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
			continue;
		}
		if (!branches_set) {
			branches_csv_path = argv[i];
			branches_set = true;
			continue;
		}
		if (!objects_set) {
			objects_csv_path = argv[i];
			objects_set = true;
			continue;
		}
		if (!memory_set) {
			memory_csv_path = argv[i];
			memory_set = true;
			continue;
		}
		fprintf(stderr,
			"ERROR: unexpected argument '%s'\n"
			"Usage: %s <saterm|kflex|baseline> <num_branches> <num_objects> "
			"<iteration_interval> <num_runs> [branches_csv] [objects_csv] [memory_csv] [--verbose]\n",
			argv[i], argv[0]);
		return 1;
	}

	/* Keep output clean for CSV-oriented benchmark runs. */
	libbpf_set_print(NULL);

	if (selected->branches_and_objects) {
		/*
		 * run_time_ns/run_cnt require runtime stats to be enabled while this
		 * FD is open; otherwise termination_time_ns may stay at 0.
		 */
		stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (stats_fd < 0) {
			fprintf(stderr,
				"ERROR: bpf_enable_stats(BPF_STATS_RUN_TIME) failed: %s\n"
				"Hint: run as root and/or enable kernel.bpf_stats_enabled=1\n",
				strerror(errno));
			goto out;
		}
	}

	if (selected->branches_obj) {
		branches_csv = fopen(branches_csv_path, "w");
		if (!branches_csv) {
			fprintf(stderr, "ERROR: failed opening %s: %s\n", branches_csv_path, strerror(errno));
			goto out;
		}
		fprintf(branches_csv, "kernel_type,num_branches,run,verification_time_ns\n");

		if (run_branch_sweep(selected->tag, selected->branches_obj, max_branches, step, num_runs,
				     branches_csv, verbose) != 0)
			goto out;
	}

	if (selected->objects_obj) {
		bool use_proc = (strcmp(selected->tag, "kflex") == 0 && bpf_throw_proc_available());

		objects_csv = fopen(objects_csv_path, "w");
		if (!objects_csv) {
			fprintf(stderr, "ERROR: failed opening %s: %s\n", objects_csv_path, strerror(errno));
			goto out;
		}
		if (use_proc)
			fprintf(objects_csv, "kernel_type,num_objects,run,termination_time_ns,stack_walk_time_ns\n");
		else
			fprintf(objects_csv, "kernel_type,num_objects,run,termination_time_ns\n");

		if (run_object_sweep(selected->tag, selected->objects_obj, max_objects, step, num_runs,
				     objects_csv, use_proc) != 0)
			goto out;
	}

	memory_csv = fopen(memory_csv_path, "w");
	if (!memory_csv) {
		fprintf(stderr, "ERROR: failed opening %s: %s\n", memory_csv_path, strerror(errno));
		goto out;
	}
	fprintf(memory_csv, "kernel_type,num_objects,run,mem_avail_before_kb,mem_avail_after_kb,mem_free_before_kb,mem_free_after_kb,xlated_prog_len,jited_prog_len\n");

	if (run_memory_sweep(selected->tag, selected->memory_obj, max_objects, step, num_runs,
			    memory_csv) != 0)
		goto out;

	if (selected->branches_and_objects)
		printf("Wrote CSVs: %s, %s, %s\n", branches_csv_path, objects_csv_path, memory_csv_path);
	else
		printf("Wrote memory CSV (baseline): %s\n", memory_csv_path);
	rc = 0;

out:
	if (branches_csv)
		fclose(branches_csv);
	if (objects_csv)
		fclose(objects_csv);
	if (memory_csv)
		fclose(memory_csv);
	if (stats_fd >= 0)
		close(stats_fd);
	return rc;
}
