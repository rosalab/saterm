/*
 * Unified BPF program loader for measuring load-time memory overhead.
 *
 * Loads a .kern.o file, measures MemAvailable/MemFree before and after
 * loading, retrieves xlated/jited program lengths, and prints a single
 * CSV row to stdout.  Works with any BPF object file.
 *
 * Usage:
 *   ./measure.user <kern.o>
 *
 * Output (stdout, one line):
 *   mem_avail_before_kb,mem_avail_after_kb,mem_free_before_kb,mem_free_after_kb,xlated_prog_len,jited_prog_len
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
	long mem_avail_before = 0, mem_avail_after = 0;
	long mem_free_before = 0, mem_free_after = 0;
	__u32 xlated_len = 0, jited_len = 0;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	const char *kern_o;
	int prog_fd;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <kern.o>\n", argv[0]);
		return 1;
	}
	kern_o = argv[1];

	/* Suppress libbpf info logs so only our CSV goes to stdout */
	libbpf_set_print(NULL);

	read_meminfo_kb("MemAvailable", &mem_avail_before);
	read_meminfo_kb("MemFree", &mem_free_before);

	obj = bpf_object__open_file(kern_o, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening %s: %s\n", kern_o,
			strerror(errno));
		return 1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading %s failed\n", kern_o);
		bpf_object__close(obj);
		return 1;
	}

	read_meminfo_kb("MemAvailable", &mem_avail_after);
	read_meminfo_kb("MemFree", &mem_free_after);

	/* Find the first program in the object */
	prog = bpf_object__next_program(obj, NULL);
	if (prog) {
		prog_fd = bpf_program__fd(prog);
		if (prog_fd >= 0)
			get_prog_sizes(prog_fd, &xlated_len, &jited_len);
	}

	printf("%ld,%ld,%ld,%ld,%u,%u\n",
	       mem_avail_before, mem_avail_after,
	       mem_free_before, mem_free_after,
	       xlated_len, jited_len);

	bpf_object__close(obj);
	return 0;
}
