/*
 * Figure-8 worst-case verifier benchmark runner.
 *
 * Usage:
 *   ./figure8_worstcase.user <saterm|kflex> [output_csv] [--runs N] [--verbose]
 *
 * The runner is load-only: it rebuilds one BPF object per sweep point, times
 * verifier load via bpftool, and captures the corresponding kernel-log suffix
 * to extract either exact unwind metadata bytes or a vzalloc-sum fallback.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BPFTOOL_REL_PATH "../../../linux/tools/bpf/bpftool/bpftool"
#define KMSG_PATH "/dev/kmsg"
#define KMSG_MARKER_PREFIX "figure8_worstcase_marker"
#define LOAD_TIMEOUT_SECS 30

struct shape_config {
	const char *shape;
	const char *object_file;
	const char *param_name;
	int start;
	int stop;
	int step;
};

struct verifier_stats {
	uint64_t verification_time_ns;
	uint64_t processed_insns;
	uint64_t max_states_per_insn;
	uint64_t total_states;
	uint64_t peak_states;
};

struct memory_window {
	bool saw_marker;
	bool have_unwind_total;
	bool have_vzalloc_sum;
	uint64_t unwind_total_bytes;
	uint64_t vzalloc_sum_bytes;
	char *suffix;
};

struct sample_result {
	struct verifier_stats stats;
	uint64_t unwind_bytes;
	const char *memory_source;
};

enum load_status {
	LOAD_STATUS_OK = 0,
	LOAD_STATUS_ERROR = -1,
	LOAD_STATUS_VARIANT_MISMATCH = -2,
};

static const struct shape_config shapes[] = {
	{
		.shape = "rt_fanin",
		.object_file = "rt_fanin.kern.o",
		.param_name = "FANIN_SLOTS",
		.start = 2,
		.stop = 16,
		.step = 2,
	},
	{
		.shape = "rt_ladder",
		.object_file = "rt_ladder.kern.o",
		.param_name = "LADDER_DEPTH",
		.start = 1,
		.stop = 8,
		.step = 1,
	},
	{
		.shape = "rt_many_pcs",
		.object_file = "rt_many_pcs.kern.o",
		.param_name = "THROW_PCS",
		.start = 8,
		.stop = 64,
		.step = 8,
	},
	{
		.shape = "mem_big_single_desc",
		.object_file = "mem_big_single_desc.kern.o",
		.param_name = "FRAME_BYTES",
		.start = 56,
		.stop = 504,
		.step = 56,
	},
	{
		.shape = "mem_deep_ladder",
		.object_file = "mem_deep_ladder.kern.o",
		.param_name = "FRAME_DEPTH",
		.start = 1,
		.stop = 8,
		.step = 1,
	},
	{
		.shape = "mem_many_big_descs",
		.object_file = "mem_many_big_descs.kern.o",
		.param_name = "DESC_PCS",
		.start = 8,
		.stop = 64,
		.step = 8,
	},
};

static bool use_build_ids;
static uid_t build_uid;
static gid_t build_gid;

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <saterm|kflex> [output_csv] [--runs N] [--verbose]\n",
		prog);
}

static int append_text(char **buf, size_t *cap, size_t *len, const char *chunk)
{
	size_t need = strlen(chunk);

	if (*len + need + 1 > *cap) {
		size_t new_cap = *cap ? *cap : 4096;
		char *new_buf;

		while (*len + need + 1 > new_cap)
			new_cap *= 2;
		new_buf = realloc(*buf, new_cap);
		if (!new_buf)
			return -1;
		*buf = new_buf;
		*cap = new_cap;
	}

	memcpy(*buf + *len, chunk, need);
	*len += need;
	(*buf)[*len] = '\0';
	return 0;
}

static int chdir_to_executable_dir(void)
{
	char exe_path[PATH_MAX];
	char *slash;
	ssize_t len;

	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len < 0) {
		fprintf(stderr, "ERROR: readlink(/proc/self/exe) failed: %s\n", strerror(errno));
		return -1;
	}

	exe_path[len] = '\0';
	slash = strrchr(exe_path, '/');
	if (!slash) {
		fprintf(stderr, "ERROR: executable path does not contain a directory\n");
		return -1;
	}
	*slash = '\0';

	if (chdir(exe_path) != 0) {
		fprintf(stderr, "ERROR: chdir(%s) failed: %s\n", exe_path, strerror(errno));
		return -1;
	}
	return 0;
}

static int run_command_capture(const char *cmd, char **output_out)
{
	FILE *pipe;
	char line[4096];
	char *output = NULL;
	size_t cap = 0;
	size_t len = 0;
	int status;

	pipe = popen(cmd, "r");
	if (!pipe) {
		fprintf(stderr, "ERROR: popen failed for command '%s': %s\n", cmd, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), pipe)) {
		if (append_text(&output, &cap, &len, line) != 0) {
			fprintf(stderr, "ERROR: failed growing command output buffer\n");
			free(output);
			pclose(pipe);
			return -1;
		}
	}

	status = pclose(pipe);
	if (!output) {
		output = strdup("");
		if (!output)
			return -1;
	}

	*output_out = output;
	if (status == -1)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

static int run_command_capture_with_ids(const char *cmd, uid_t uid, gid_t gid, char **output_out)
{
	uid_t old_euid = geteuid();
	gid_t old_egid = getegid();
	int rc;

	if (old_euid != 0)
		return run_command_capture(cmd, output_out);

	if (setegid(gid) != 0) {
		fprintf(stderr, "ERROR: setegid(%u) failed: %s\n", gid, strerror(errno));
		return -1;
	}
	if (seteuid(uid) != 0) {
		fprintf(stderr, "ERROR: seteuid(%u) failed: %s\n", uid, strerror(errno));
		setegid(old_egid);
		return -1;
	}

	rc = run_command_capture(cmd, output_out);

	if (seteuid(old_euid) != 0) {
		fprintf(stderr, "ERROR: restoring euid %u failed: %s\n",
			old_euid, strerror(errno));
		return -1;
	}
	if (setegid(old_egid) != 0) {
		fprintf(stderr, "ERROR: restoring egid %u failed: %s\n",
			old_egid, strerror(errno));
		return -1;
	}

	return rc;
}

static int parse_verifier_stats(const char *text, struct verifier_stats *stats)
{
	char *copy;
	char *line;
	char *save = NULL;
	bool have_time = false;
	bool have_processed = false;

	memset(stats, 0, sizeof(*stats));
	copy = strdup(text);
	if (!copy)
		return -1;

	for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		unsigned long long time_usec = 0;
		unsigned long long processed = 0, limit = 0;
		unsigned long long max_states = 0, total_states = 0, peak_states = 0;
		unsigned long long mark_read = 0;
		char *p = strstr(line, "verification time ");

		if (p && (sscanf(p, "verification time %llu usec", &time_usec) == 1 ||
			  sscanf(p, "verification time %llu  usec", &time_usec) == 1)) {
			stats->verification_time_ns = time_usec * 1000ULL;
			have_time = true;
			continue;
		}

		if (sscanf(line,
			   "processed %llu insns (limit %llu) max_states_per_insn %llu total_states %llu peak_states %llu mark_read %llu",
			   &processed, &limit, &max_states, &total_states, &peak_states,
			   &mark_read) >= 5) {
			stats->processed_insns = processed;
			stats->max_states_per_insn = max_states;
			stats->total_states = total_states;
			stats->peak_states = peak_states;
			have_processed = true;
		}
	}

	free(copy);
	return have_time && have_processed ? 0 : -1;
}

static int write_kmsg_marker(char *marker, size_t marker_sz)
{
	FILE *fp;
	struct timespec now = {};
	int rc;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		fprintf(stderr, "ERROR: clock_gettime failed for marker: %s\n", strerror(errno));
		return -1;
	}

	rc = snprintf(marker, marker_sz, "%s:%d:%lld:%ld",
		      KMSG_MARKER_PREFIX, getpid(),
		      (long long)now.tv_sec, now.tv_nsec);
	if (rc <= 0 || rc >= (int)marker_sz) {
		fprintf(stderr, "ERROR: marker buffer too small\n");
		return -1;
	}

	fp = fopen(KMSG_PATH, "w");
	if (!fp) {
		fprintf(stderr, "ERROR: opening %s failed: %s\n", KMSG_PATH, strerror(errno));
		return -1;
	}
	if (fprintf(fp, "<6>%s\n", marker) < 0) {
		fprintf(stderr, "ERROR: writing %s failed: %s\n", KMSG_PATH, strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

static int read_kernel_log_window(const char *marker, struct memory_window *window)
{
	FILE *pipe;
	char line[4096];
	char *suffix = NULL;
	size_t cap = 0;
	size_t len = 0;
	bool capture = false;

	memset(window, 0, sizeof(*window));
	pipe = popen("dmesg", "r");
	if (!pipe) {
		fprintf(stderr, "ERROR: popen(dmesg) failed: %s\n", strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), pipe)) {
		char *p;
		unsigned long long value = 0;

		if (strstr(line, marker)) {
			capture = true;
			window->saw_marker = true;
			window->have_unwind_total = false;
			window->have_vzalloc_sum = false;
			window->unwind_total_bytes = 0;
			window->vzalloc_sum_bytes = 0;
			len = 0;
			if (suffix)
				suffix[0] = '\0';
			continue;
		}
		if (!capture)
			continue;

		if (append_text(&suffix, &cap, &len, line) != 0) {
			fprintf(stderr, "ERROR: failed growing kernel-log buffer\n");
			free(suffix);
			pclose(pipe);
			return -1;
		}

		p = strstr(line, "total unwind info memory overhead: ");
		if (p && sscanf(p, "total unwind info memory overhead: %llu bytes", &value) == 1) {
			window->unwind_total_bytes = value;
			window->have_unwind_total = true;
		}

		p = strstr(line, "vzalloc size: ");
		if (p && sscanf(p, "vzalloc size: %llu bytes", &value) == 1) {
			window->vzalloc_sum_bytes += value;
			window->have_vzalloc_sum = true;
		}
	}

	pclose(pipe);
	window->suffix = suffix ? suffix : strdup("");
	if (!window->suffix)
		return -1;
	if (!window->saw_marker) {
		free(window->suffix);
		window->suffix = NULL;
		return -1;
	}
	return 0;
}

static int build_object(const char *object_file, const char *variant_macro,
			const char *param_name, int param_value, bool verbose)
{
	char cmd[512];
	char *output = NULL;
	int rc;

	rc = snprintf(cmd, sizeof(cmd),
		      "make -s -B %s EXTRA_CFLAGS='-D%s -D%s=%d' 2>&1",
		      object_file, variant_macro, param_name, param_value);
	if (rc <= 0 || rc >= (int)sizeof(cmd)) {
		fprintf(stderr, "ERROR: build command too long\n");
		return -1;
	}

	if (use_build_ids)
		rc = run_command_capture_with_ids(cmd, build_uid, build_gid, &output);
	else
		rc = run_command_capture(cmd, &output);
	if (verbose && output && output[0] != '\0')
		fprintf(stderr, "%s", output);
	if (rc != 0) {
		fprintf(stderr, "ERROR: build failed: %s\n", cmd);
		if (output && output[0] != '\0')
			fprintf(stderr, "%s", output);
		free(output);
		return -1;
	}

	free(output);
	return 0;
}

static bool same_file_path(const char *path_a, const char *path_b)
{
	struct stat st_a, st_b;

	if (strcmp(path_a, path_b) == 0)
		return true;
	if (stat(path_a, &st_a) != 0 || stat(path_b, &st_b) != 0)
		return false;
	return st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino;
}

static int copy_file_atomic(const char *src_path, const char *dst_path)
{
	char tmp_path[PATH_MAX];
	FILE *src = NULL;
	FILE *dst = NULL;
	char buf[8192];
	size_t nread;
	int rc;

	rc = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", dst_path, getpid());
	if (rc <= 0 || rc >= (int)sizeof(tmp_path)) {
		fprintf(stderr, "ERROR: temporary sync path too long for %s\n", dst_path);
		return -1;
	}

	src = fopen(src_path, "rb");
	if (!src) {
		fprintf(stderr, "ERROR: opening %s for sync failed: %s\n",
			src_path, strerror(errno));
		return -1;
	}

	dst = fopen(tmp_path, "wb");
	if (!dst) {
		fprintf(stderr, "ERROR: opening %s for sync failed: %s\n",
			tmp_path, strerror(errno));
		fclose(src);
		return -1;
	}

	while ((nread = fread(buf, 1, sizeof(buf), src)) > 0) {
		if (fwrite(buf, 1, nread, dst) != nread) {
			fprintf(stderr, "ERROR: writing %s failed during sync: %s\n",
				tmp_path, strerror(errno));
			fclose(dst);
			fclose(src);
			unlink(tmp_path);
			return -1;
		}
	}

	if (ferror(src)) {
		fprintf(stderr, "ERROR: reading %s failed during sync: %s\n",
			src_path, strerror(errno));
		fclose(dst);
		fclose(src);
		unlink(tmp_path);
		return -1;
	}

	if (fclose(dst) != 0) {
		fprintf(stderr, "ERROR: closing %s failed during sync: %s\n",
			tmp_path, strerror(errno));
		fclose(src);
		unlink(tmp_path);
		return -1;
	}
	dst = NULL;

	if (fclose(src) != 0) {
		fprintf(stderr, "ERROR: closing %s failed during sync: %s\n",
			src_path, strerror(errno));
		unlink(tmp_path);
		return -1;
	}
	src = NULL;

	if (rename(tmp_path, dst_path) != 0) {
		fprintf(stderr, "ERROR: renaming %s to %s failed during sync: %s\n",
			tmp_path, dst_path, strerror(errno));
		unlink(tmp_path);
		return -1;
	}

	return 0;
}

static int sync_output_copy(const char *src_path, const char *dst_path, bool verbose)
{
	if (same_file_path(src_path, dst_path))
		return 0;
	if (copy_file_atomic(src_path, dst_path) != 0)
		return -1;
	if (verbose)
		fprintf(stderr, "Synced CSV: %s -> %s\n", src_path, dst_path);
	return 0;
}

static int load_object_sample(const char *bpftool_path, const char *object_file,
			      bool verbose, struct sample_result *result)
{
	char marker[128];
	char pin_path[256];
	char cmd[1024];
	char *output = NULL;
	struct memory_window window;
	struct timespec now = {};
	int rc;
	int cmd_rc;

	memset(result, 0, sizeof(*result));
	memset(&window, 0, sizeof(window));

	if (write_kmsg_marker(marker, sizeof(marker)) != 0)
		return -1;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		fprintf(stderr, "ERROR: clock_gettime failed for pin path: %s\n", strerror(errno));
		return -1;
	}

	rc = snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/figure8_worstcase_%d_%lld_%ld",
		      getpid(), (long long)now.tv_sec, now.tv_nsec);
	if (rc <= 0 || rc >= (int)sizeof(pin_path)) {
		fprintf(stderr, "ERROR: pin path too long\n");
		return -1;
	}

	rc = snprintf(cmd, sizeof(cmd), "%s -d prog load %s %s 2>&1",
		      bpftool_path, object_file, pin_path);
	if (rc <= 0 || rc >= (int)sizeof(cmd)) {
		fprintf(stderr, "ERROR: bpftool command too long\n");
		return -1;
	}

	{
		char timed_cmd[1152];

		rc = snprintf(timed_cmd, sizeof(timed_cmd),
			      "timeout --foreground --signal=TERM --kill-after=5s %ds %s",
			      LOAD_TIMEOUT_SECS, cmd);
		if (rc <= 0 || rc >= (int)sizeof(timed_cmd)) {
			fprintf(stderr, "ERROR: timed bpftool command too long\n");
			return -1;
		}
		cmd_rc = run_command_capture(timed_cmd, &output);
	}
	unlink(pin_path);

	if (usleep(20000) != 0 && errno != EINTR) {
		fprintf(stderr, "WARN: usleep after load failed: %s\n", strerror(errno));
	}

	if (read_kernel_log_window(marker, &window) != 0) {
		fprintf(stderr, "ERROR: failed to locate kernel-log marker '%s'\n", marker);
		free(output);
		return -1;
	}

	if (verbose) {
		if (output && output[0] != '\0')
			fprintf(stderr, "%s", output);
		if (window.suffix && window.suffix[0] != '\0')
			fprintf(stderr, "%s", window.suffix);
	}

	if (cmd_rc != 0) {
		bool missing_variant_kfunc = false;

		if (output &&
		    ((strstr(output, "bpf_die_kfunc") && strstr(output, "not found in kernel or module BTFs")) ||
		     (strstr(output, "bpf_throw") && strstr(output, "not found in kernel or module BTFs")))) {
			missing_variant_kfunc = true;
		}

		if (cmd_rc == 124) {
			fprintf(stderr,
				"ERROR: bpftool load timed out after %d seconds: %s\n",
				LOAD_TIMEOUT_SECS, cmd);
		} else {
			fprintf(stderr, "ERROR: bpftool load failed: %s\n", cmd);
		}
		if (output && output[0] != '\0')
			fprintf(stderr, "%s", output);
		free(window.suffix);
		free(output);
		return missing_variant_kfunc ? LOAD_STATUS_VARIANT_MISMATCH : LOAD_STATUS_ERROR;
	}

	if (!output || parse_verifier_stats(output, &result->stats) != 0) {
		fprintf(stderr, "ERROR: failed to parse verifier stats from bpftool output\n");
		if (output && output[0] != '\0')
			fprintf(stderr, "%s", output);
		free(window.suffix);
		free(output);
		return -1;
	}

	if (window.have_unwind_total) {
		result->unwind_bytes = window.unwind_total_bytes;
		result->memory_source = "unwind_total";
	} else if (window.have_vzalloc_sum) {
		result->unwind_bytes = window.vzalloc_sum_bytes;
		result->memory_source = "vzalloc_sum";
	} else {
		fprintf(stderr,
			"ERROR: kernel log contained neither exact unwind bytes nor vzalloc fallback\n");
		if (window.suffix && window.suffix[0] != '\0')
			fprintf(stderr, "%s", window.suffix);
		free(window.suffix);
		free(output);
		return -1;
	}

	free(window.suffix);
	free(output);
	return 0;
}

int main(int argc, char **argv)
{
	const char *variant;
	const char *variant_macro;
	const char *output_csv = NULL;
	const char *bpftool_path = BPFTOOL_REL_PATH;
	const char *convenience_output = NULL;
	char canonical_output[64];
	char default_output[64];
	FILE *csv = NULL;
	bool verbose = false;
	bool fatal_variant_mismatch = false;
	int runs = 3;
	size_t i;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (chdir_to_executable_dir() != 0)
		return 1;

	variant = argv[1];
	if (strcmp(variant, "saterm") == 0) {
		variant_macro = "BENCH_VARIANT_SATERM";
	} else if (strcmp(variant, "kflex") == 0) {
		variant_macro = "BENCH_VARIANT_KFLEX";
	} else {
		fprintf(stderr, "ERROR: variant must be 'saterm' or 'kflex'\n");
		return 1;
	}

	for (i = 2; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
			continue;
		}
		if (strcmp(argv[i], "--runs") == 0) {
			if (i + 1 >= (size_t)argc) {
				fprintf(stderr, "ERROR: --runs requires an integer argument\n");
				return 1;
			}
			runs = atoi(argv[++i]);
			if (runs <= 0) {
				fprintf(stderr, "ERROR: --runs must be > 0\n");
				return 1;
			}
			continue;
		}
		if (!output_csv) {
			output_csv = argv[i];
			continue;
		}
		fprintf(stderr, "ERROR: unexpected argument '%s'\n", argv[i]);
		print_usage(argv[0]);
		return 1;
	}

	if (!output_csv) {
		snprintf(default_output, sizeof(default_output), "%s_worstcase.csv", variant);
		output_csv = default_output;
	}
	snprintf(canonical_output, sizeof(canonical_output), "%s_worstcase.csv", variant);
	if (strcmp(variant, "kflex") == 0)
		convenience_output = "worstcase.csv";

	if (access(bpftool_path, X_OK) != 0) {
		fprintf(stderr, "ERROR: bpftool is not executable at %s: %s\n",
			bpftool_path, strerror(errno));
		return 1;
	}

	if (geteuid() == 0) {
		const char *sudo_uid = getenv("SUDO_UID");
		const char *sudo_gid = getenv("SUDO_GID");

		if (sudo_uid && sudo_gid) {
			build_uid = (uid_t)strtoul(sudo_uid, NULL, 10);
			build_gid = (gid_t)strtoul(sudo_gid, NULL, 10);
			use_build_ids = true;
		}
	}

	csv = fopen(output_csv, "w");
	if (!csv) {
		fprintf(stderr, "ERROR: opening %s failed: %s\n", output_csv, strerror(errno));
		return 1;
	}

	fprintf(csv,
		"kernel_type,shape,param_name,param_value,run,verification_time_ns,"
		"processed_insns,max_states_per_insn,total_states,peak_states,"
		"unwind_bytes,memory_source\n");

	for (i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
		const struct shape_config *shape = &shapes[i];
		int param_value;
		bool stop_shape = false;

		for (param_value = shape->start; param_value <= shape->stop;
		     param_value += shape->step) {
			int run;

			if (build_object(shape->object_file, variant_macro,
					 shape->param_name, param_value, verbose) != 0) {
				fprintf(stderr,
					"WARNING: stopping %s at %s=%d after build failure\n",
					shape->shape, shape->param_name, param_value);
				break;
			}

			for (run = 1; run <= runs; run++) {
				struct sample_result result;
				int load_rc;

				load_rc = load_object_sample(bpftool_path, shape->object_file,
							     verbose, &result);
				if (load_rc != 0) {
					if (load_rc == LOAD_STATUS_VARIANT_MISMATCH) {
						fprintf(stderr,
							"ERROR: selected variant '%s' does not match the running kernel\n",
							variant);
						fatal_variant_mismatch = true;
						stop_shape = true;
						break;
					}
					fprintf(stderr,
						"WARNING: stopping %s at %s=%d after load failure (run %d)\n",
						shape->shape, shape->param_name, param_value, run);
					stop_shape = true;
					break;
				}

				fprintf(csv,
					"%s,%s,%s,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu,%s\n",
					variant, shape->shape, shape->param_name, param_value, run,
					(unsigned long long)result.stats.verification_time_ns,
					(unsigned long long)result.stats.processed_insns,
					(unsigned long long)result.stats.max_states_per_insn,
					(unsigned long long)result.stats.total_states,
					(unsigned long long)result.stats.peak_states,
					(unsigned long long)result.unwind_bytes,
					result.memory_source);
				fflush(csv);
			}

			if (stop_shape)
				break;
		}

		if (fatal_variant_mismatch)
			break;
	}

	fclose(csv);
	if (fatal_variant_mismatch)
		return 1;
	if (sync_output_copy(output_csv, canonical_output, verbose) != 0)
		return 1;
	if (convenience_output &&
	    sync_output_copy(canonical_output, convenience_output, verbose) != 0)
		return 1;
	printf("Wrote %s\n", output_csv);
	if (!same_file_path(output_csv, canonical_output))
		printf("Synced %s\n", canonical_output);
	if (convenience_output && !same_file_path(canonical_output, convenience_output))
		printf("Synced %s\n", convenience_output);
	return 0;
}
