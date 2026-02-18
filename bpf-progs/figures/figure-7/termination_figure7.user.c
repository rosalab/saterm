/*
 * Figure-7 benchmark runner.
 *
 * Runs compile-time sweeps for three programs and writes CSV output.
 *
 * Usage:
 *   ./termination_figure7.user <num_runs> <iteration_interval>
 *                              <max_iteration_count> [output_csv] [--verbose]
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_saterm_test 470
struct sweep_program {
	const char *category;
	const char *object_file;
	const char *macro_name;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	(void)level;
	return vfprintf(stderr, format, args);
}

static uint64_t get_program_runtime(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return 0;

	return info.run_time_ns;
}

static uint64_t read_alloc_ns(struct bpf_object *obj)
{
	__u32 key = 0;
	__u64 alloc_ns = 0;
	int map_fd;

	map_fd = bpf_object__find_map_fd_by_name(obj, "alloc_time_map");
	if (map_fd < 0)
		return 0;

	if (bpf_map_lookup_elem(map_fd, &key, &alloc_ns) != 0)
		return 0;

	return alloc_ns;
}

static int run_once(const char *kern_o, uint64_t *delta_out, uint64_t *alloc_ns_out)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL;
	uint64_t runtime_before;
	uint64_t runtime_after;
	int prog_fd;
	int ret = 0;

	obj = bpf_object__open_file(kern_o, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening %s failed: %s\n", kern_o,
			strerror(-libbpf_get_error(obj)));
		return -1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading %s failed\n", kern_o);
		ret = -1;
		goto out;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		fprintf(stderr, "ERROR: no program found in %s\n", kern_o);
		ret = -1;
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: invalid program fd for %s\n", kern_o);
		ret = -1;
		goto out;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: attach failed for %s: %ld\n", kern_o,
			libbpf_get_error(link));
		link = NULL;
		ret = -1;
		goto out;
	}

	runtime_before = get_program_runtime(prog_fd);
	syscall(__NR_saterm_test);
	runtime_after = get_program_runtime(prog_fd);
	*delta_out = runtime_after - runtime_before;
	if (alloc_ns_out)
		*alloc_ns_out = read_alloc_ns(obj);

out:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	return ret;
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

static int append_program_rows(FILE *csv, const struct sweep_program *prog,
			       int num_runs, int max_count, int step_count,
			       bool verbose)
{
	int count;

	for (count = 0; count <= max_count; count += step_count) {
		int run;

		if (run_make_compile(prog->object_file, prog->macro_name, count) != 0)
			return -1;

		for (run = 1; run <= num_runs; run++) {
			uint64_t delta = 0;
			uint64_t alloc_ns = 0;
			uint64_t adjusted_runtime;

			if (run_once(prog->object_file, &delta, &alloc_ns) != 0) {
				fprintf(stderr,
					"ERROR: failed category=%s count=%d run=%d\n",
					prog->category, count, run);
				return -1;
			}

			adjusted_runtime = delta;
			if (strcmp(prog->category, "real_free") == 0)
				adjusted_runtime = (delta > alloc_ns) ? (delta - alloc_ns) : 0;
			if (verbose && strcmp(prog->category, "real_free") == 0) {
				fprintf(stderr,
					"DEBUG: category=%s count=%d run=%d alloc_delta_ns=%llu total_runtime_ns=%llu adjusted_runtime_ns=%llu\n",
					prog->category, count, run,
					(unsigned long long)alloc_ns,
					(unsigned long long)delta,
					(unsigned long long)adjusted_runtime);
			}

			fprintf(csv, "%s,%d,%d,%llu,%llu,%llu\n",
				prog->category, count, run,
				(unsigned long long)adjusted_runtime,
				(unsigned long long)alloc_ns,
				(unsigned long long)delta);
		}
		fflush(csv);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int num_runs;
	int iteration_interval;
	int max_iteration_count;
	bool verbose = false;
	bool output_set = false;
	const char *output_csv = "figure7_results.csv";
	FILE *csv = NULL;
	struct sweep_program programs[] = {
		{
			.category = "stubbed_helper",
			.object_file = "termination_stubbed.kern.o",
			.macro_name = "MAX_HELPERS",
		},
		{
			.category = "stubbed_helper_expensive",
			.object_file = "termination_stubbed_expensive.kern.o",
			.macro_name = "MAX_HELPERS",
		},
		{
			.category = "unstubbed_helper",
			.object_file = "termination_unstubbed.kern.o",
			.macro_name = "MAX_HELPERS",
		},
		{
			.category = "unstubbed_helper_expensive",
			.object_file = "termination_unstubbed_expensive.kern.o",
			.macro_name = "MAX_HELPERS",
		},
		/*
		{
			.category = "real_free",
			.object_file = "termination_realfree.kern.o",
			.macro_name = "MAX_HELPERS",
		},
		*/
		{
			.category = "baseline",
			.object_file = "termination_baseline.kern.o",
			.macro_name = "MAX_ITERS",
		},
		{
			.category = "empty",
			.object_file = "termination_empty.kern.o",
			.macro_name = "MAX_ITERS",
		},
		{
			.category = "empty_die",
			.object_file = "termination_empty_die.kern.o",
			.macro_name = "MAX_ITERS",
		},
	};
	const size_t num_programs = sizeof(programs) / sizeof(programs[0]);
	int i;

	if (argc < 4) {
		fprintf(stderr,
			"Usage: %s <num_runs> <iteration_interval> "
			"<max_iteration_count> [output_csv] [--verbose]\n",
			argv[0]);
		return 1;
	}

	num_runs = atoi(argv[1]);
	iteration_interval = atoi(argv[2]);
	max_iteration_count = atoi(argv[3]);
	for (i = 4; i < argc; i++) {
		if (strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
		} else if (!output_set) {
			output_csv = argv[i];
			output_set = true;
		} else {
			fprintf(stderr, "ERROR: unexpected argument: %s\n", argv[i]);
			fprintf(stderr,
				"Usage: %s <num_runs> <iteration_interval> "
				"<max_iteration_count> [output_csv] [--verbose]\n",
				argv[0]);
			return 1;
		}
	}

	if (num_runs <= 0 || iteration_interval <= 0 || max_iteration_count < 0) {
		fprintf(stderr, "ERROR: invalid numeric arguments\n");
		return 1;
	}
	/* Verbose mode prints full libbpf diagnostics. */
	if (verbose)
		libbpf_set_print(libbpf_print_fn);
	else
		libbpf_set_print(NULL);

	if (system("make -s termination_figure7.user") != 0) {
		fprintf(stderr, "ERROR: failed to ensure userspace binary build\n");
		return 1;
	}

	csv = fopen(output_csv, "w");
	if (!csv) {
		fprintf(stderr, "ERROR: failed to open %s: %s\n", output_csv, strerror(errno));
		return 1;
	}
	fprintf(csv, "category,count,run,runtime_ns,alloc_ns,total_runtime_ns\n");

	for (i = 0; i < (int)num_programs; i++) {
		if (append_program_rows(csv, &programs[i], num_runs,
					max_iteration_count, iteration_interval, verbose) != 0) {
			fclose(csv);
			return 1;
		}
	}

	fclose(csv);
	printf("Wrote CSV: %s\n", output_csv);
	return 0;
}
