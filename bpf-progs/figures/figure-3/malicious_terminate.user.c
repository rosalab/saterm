#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct control_args {
    __u32 work_iters;
    __u32 mode;
    __u64 time_limit_ns;
};

enum experiment_mode {
    EXP_MODE_NO_TERMINATION = 0,
    EXP_MODE_TERMINATION_IMMEDIATE = 1,
    EXP_MODE_TERMINATION_BUDGETED = 2,
};

enum termination_style {
    TERM_STYLE_IMMEDIATE = 0,
    TERM_STYLE_BUDGETED = 1,
};

struct memtier_stats {
    double ops_sec;
    double avg_latency_ms;
    double max_latency_ms;
    double p99_latency_ms;
    double p999_latency_ms;
};

struct termination_stats {
    __u64 hits;
    __u64 total_elapsed_ns;
    __u64 total_completed_work_iters;
};

struct termination_stats_summary {
    __u64 hits;
    double avg_elapsed_ns_before_termination;
    double avg_completed_work_iters_before_termination;
};

#define VERIFIER_SAFE_MAX_WORK_ITERS 1048576U
#define DEFAULT_TIME_LIMIT_US 2.0
#define BPF_STATS_SYSCTL_PATH "/proc/sys/kernel/bpf_stats_enabled"

static volatile sig_atomic_t g_running = 1;
static pid_t g_redis_pid = -1;
static const char *g_redis_dir = "/tmp";
static const char *g_redis_dbfilename = "figure3_redis.rdb";
static char g_redis_host[128] = "192.168.10.1";
static unsigned int g_redis_port = 11212;
static char g_ssh_target[128] = "deimos-vm";

static void on_signal(int signo)
{
    (void)signo;
    g_running = 0;
}

static int verbose;

static const char *exp_mode_cli_name(enum experiment_mode mode)
{
    switch (mode) {
    case EXP_MODE_TERMINATION_BUDGETED:
        return "termination-budgeted";
    case EXP_MODE_TERMINATION_IMMEDIATE:
        return "termination";
    case EXP_MODE_NO_TERMINATION:
    default:
        return "no-termination";
    }
}

static const char *exp_mode_csv_name(enum experiment_mode mode)
{
    switch (mode) {
    case EXP_MODE_TERMINATION_BUDGETED:
        return "termination_budgeted";
    case EXP_MODE_TERMINATION_IMMEDIATE:
        return "termination_immediate";
    case EXP_MODE_NO_TERMINATION:
    default:
        return "no_termination";
    }
}

static int parse_exp_mode(const char *s, enum experiment_mode *out, int *both)
{
    if (!s || !out)
        return -1;
    if (!strcmp(s, "no-termination")) {
        *out = EXP_MODE_NO_TERMINATION;
        return 0;
    }
    if (!strcmp(s, "termination")) {
        *out = EXP_MODE_TERMINATION_IMMEDIATE;
        return 0;
    }
    if (!strcmp(s, "both")) {
        if (both)
            *both = 1;
        *out = EXP_MODE_NO_TERMINATION;
        return 0;
    }
    return -1;
}

static const char *termination_style_name(enum termination_style style)
{
    switch (style) {
    case TERM_STYLE_BUDGETED:
        return "budgeted";
    case TERM_STYLE_IMMEDIATE:
    default:
        return "immediate";
    }
}

static int parse_termination_style(const char *s, enum termination_style *out)
{
    if (!s || !out)
        return -1;
    if (!strcmp(s, "immediate")) {
        *out = TERM_STYLE_IMMEDIATE;
        return 0;
    }
    if (!strcmp(s, "budgeted")) {
        *out = TERM_STYLE_BUDGETED;
        return 0;
    }
    return -1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    if (!verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
    printf("Usage: %s --tracepoint CATEGORY:EVENT [options]\n", prog);
    printf("Options:\n");
    printf("  --work-iters N      loop work iterations for no-termination mode (default 1)\n");
    printf("  --die-after N       compatibility alias for --work-iters\n");
    printf("  --exp-mode MODE     no-termination|termination|both (default no-termination)\n");
    printf("  --termination-style STYLE\n");
    printf("                     immediate|budgeted (default immediate)\n");
    printf("  --time-limit-us F   required time budget in microseconds for budgeted termination\n");
    printf("  --max [N]           iterate work-iters from 0..N (inclusive, default/cap %u)\n",
           VERIFIER_SAFE_MAX_WORK_ITERS);
    printf("  --step N            step size for --max iterations (default 1)\n");
    printf("  --runs N            memtier runs per point, averaged (default 3)\n");
    printf("  --test-time N       memtier test duration in seconds (default 120)\n");
    printf("  --csv PATH          write results to CSV (default figure3_results.csv)\n");
    printf("  --raw-json PATH     save latest memtier output and append archive to PATH.archive\n");
    printf("  --redis-host HOST   Redis bind address and memtier server host (default %s)\n",
           g_redis_host);
    printf("  --redis-port PORT   Redis port and memtier server port (default %u)\n",
           g_redis_port);
    printf("  --ssh-target HOST   SSH target used to run memtier (default %s)\n",
           g_ssh_target);
    printf("  --no-redis          don't start redis-server (default: start)\n");
    printf("  --no-memtier        don't run memtier benchmark (default: run)\n");
    printf("  --verbose           print best-effort BPF load debug output (libbpf + verifier + dmesg)\n");
    printf("  --no-verify-reload  disable per-point prog reload/detach verification in --max sweeps\n");
}

static int split_tracepoint(const char *tp, char *cat, size_t cat_sz,
                            char *evt, size_t evt_sz)
{
    const char *colon = strchr(tp, ':');
    if (!colon)
        return -1;
    size_t cat_len = (size_t)(colon - tp);
    size_t evt_len = strlen(colon + 1);
    if (cat_len == 0 || evt_len == 0 || cat_len >= cat_sz || evt_len >= evt_sz)
        return -1;
    memcpy(cat, tp, cat_len);
    cat[cat_len] = '\0';
    snprintf(evt, evt_sz, "%s", colon + 1);
    return 0;
}

struct bpf_session {
    struct bpf_object *obj;
    struct bpf_link *link;
    int ctl_fd;
    int term_stats_fd;
    int prog_fd;
    __u32 prog_id;
    char *kernel_log_buf;
    char *prog_log_buf;
};

static void bpf_session_close(struct bpf_session *session)
{
    if (!session)
        return;

    if (session->link)
        bpf_link__destroy(session->link);
    if (session->obj)
        bpf_object__close(session->obj);
    free(session->kernel_log_buf);
    free(session->prog_log_buf);

    session->obj = NULL;
    session->link = NULL;
    session->ctl_fd = -1;
    session->term_stats_fd = -1;
    session->prog_fd = -1;
    session->prog_id = 0;
    session->kernel_log_buf = NULL;
    session->prog_log_buf = NULL;
}

#define VERIFIER_LOG_LEVEL_CONCISE (1 | 4) /* BPF_LOG_LEVEL1 | BPF_LOG_STATS */
#define VERIFIER_LOG_BUF_SIZE (8u << 20)

static void dump_kernel_log(const char *title, const char *buf)
{
    if (!verbose || !buf || !buf[0])
        return;

    fprintf(stderr, "----- %s -----\n%s\n", title, buf);
}

static void get_now_ts(char *buf, size_t sz)
{
    time_t now = time(NULL);
    struct tm tm;

    if (!buf || sz == 0)
        return;

    if (now == (time_t)-1 || !localtime_r(&now, &tm)) {
        buf[0] = '\0';
        return;
    }
    if (strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm) == 0)
        buf[0] = '\0';
}

static void dump_dmesg_since(const char *since_ts)
{
    char cmd[256];
    char line[1024];
    FILE *fp;

    if (!verbose || !since_ts || !since_ts[0])
        return;

    snprintf(cmd, sizeof(cmd),
             "dmesg --color=never --since '%s' 2>/dev/null", since_ts);
    fp = popen(cmd, "r");
    if (!fp)
        return;

    fprintf(stderr, "----- kernel dmesg since %s -----\n", since_ts);
    while (fgets(line, sizeof(line), fp))
        fputs(line, stderr);

    pclose(fp);
}

static int get_prog_id(int prog_fd, __u32 *prog_id_out)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (prog_fd < 0 || !prog_id_out)
        return -1;
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
        return -1;

    *prog_id_out = info.id;
    return 0;
}

struct prog_runtime_stats {
    __u64 run_time_ns;
    __u64 run_cnt;
};

static int zero_termination_stats(int map_fd)
{
    int ncpus;
    __u32 key = 0;
    struct termination_stats *values;
    int rc;

    if (map_fd < 0)
        return -1;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -1;

    values = calloc((size_t)ncpus, sizeof(*values));
    if (!values)
        return -1;

    rc = bpf_map_update_elem(map_fd, &key, values, BPF_ANY);
    free(values);
    return rc;
}

static int read_termination_stats_summary(int map_fd,
                                          struct termination_stats_summary *summary)
{
    int ncpus;
    __u32 key = 0;
    struct termination_stats total = {};
    struct termination_stats *values;

    if (!summary || map_fd < 0)
        return -1;

    memset(summary, 0, sizeof(*summary));

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -1;

    values = calloc((size_t)ncpus, sizeof(*values));
    if (!values)
        return -1;

    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
        free(values);
        return -1;
    }

    for (int cpu = 0; cpu < ncpus; cpu++) {
        total.hits += values[cpu].hits;
        total.total_elapsed_ns += values[cpu].total_elapsed_ns;
        total.total_completed_work_iters += values[cpu].total_completed_work_iters;
    }
    free(values);

    summary->hits = total.hits;
    if (total.hits > 0) {
        summary->avg_elapsed_ns_before_termination =
            (double)total.total_elapsed_ns / (double)total.hits;
        summary->avg_completed_work_iters_before_termination =
            (double)total.total_completed_work_iters / (double)total.hits;
    }

    return 0;
}

struct bpf_stats_state {
    int original_value;
    int restore_needed;
};

static struct bpf_stats_state g_bpf_stats_state;

static int get_prog_runtime_stats(int prog_fd, struct prog_runtime_stats *out)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (prog_fd < 0 || !out)
        return -1;
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
        return -1;

    out->run_time_ns = info.run_time_ns;
    out->run_cnt = info.run_cnt;
    return 0;
}

static int read_bpf_stats_enabled(int *value_out)
{
    FILE *fp;
    int value;

    if (!value_out)
        return -1;

    fp = fopen(BPF_STATS_SYSCTL_PATH, "r");
    if (!fp)
        return -1;
    if (fscanf(fp, "%d", &value) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *value_out = value;
    return 0;
}

static int write_bpf_stats_enabled(int value)
{
    FILE *fp = fopen(BPF_STATS_SYSCTL_PATH, "w");

    if (!fp)
        return -1;
    if (fprintf(fp, "%d\n", value) < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int ensure_bpf_stats_enabled(struct bpf_stats_state *state)
{
    int current;

    if (!state)
        return -1;

    state->original_value = 0;
    state->restore_needed = 0;

    if (read_bpf_stats_enabled(&current) != 0) {
        fprintf(stderr, "Failed to read %s\n", BPF_STATS_SYSCTL_PATH);
        return -1;
    }

    state->original_value = current;
    if (current == 1)
        return 0;

    if (write_bpf_stats_enabled(1) != 0) {
        fprintf(stderr, "Failed to enable %s\n", BPF_STATS_SYSCTL_PATH);
        return -1;
    }

    state->restore_needed = 1;
    return 0;
}

static void restore_bpf_stats_enabled(const struct bpf_stats_state *state)
{
    if (!state || !state->restore_needed)
        return;
    if (write_bpf_stats_enabled(state->original_value) != 0) {
        fprintf(stderr, "WARNING: failed to restore %s to %d\n",
                BPF_STATS_SYSCTL_PATH, state->original_value);
    }
}

static void restore_bpf_stats_enabled_atexit(void)
{
    restore_bpf_stats_enabled(&g_bpf_stats_state);
}

static int verify_prog_gone(__u32 prog_id)
{
    int fd;

    if (!prog_id)
        return 0;

    fd = bpf_prog_get_fd_by_id(prog_id);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOENT)
        return 0;
    return -1;
}

static int bpf_session_open(struct bpf_session *session,
                            const char *category, const char *event)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    char *kernel_log_buf = NULL;
    char *prog_log_buf = NULL;
    char dmesg_since[32] = {};
    long link_err;
    int ctl_fd;
    int term_stats_fd;
    int load_err;
    int enable_verifier_logs;
    int retried_without_logs = 0;

    memset(session, 0, sizeof(*session));
    session->ctl_fd = -1;
    session->term_stats_fd = -1;
    session->prog_fd = -1;
    session->prog_id = 0;
    enable_verifier_logs = verbose;

open_obj:
    if (enable_verifier_logs) {
        get_now_ts(dmesg_since, sizeof(dmesg_since));

        kernel_log_buf = calloc(1, VERIFIER_LOG_BUF_SIZE);
        prog_log_buf = calloc(1, VERIFIER_LOG_BUF_SIZE);
        if (!kernel_log_buf || !prog_log_buf) {
            fprintf(stderr, "Failed to allocate verifier log buffer(s)\n");
            goto err;
        }

        LIBBPF_OPTS(bpf_object_open_opts, open_opts,
                    .kernel_log_buf = kernel_log_buf,
                    .kernel_log_size = VERIFIER_LOG_BUF_SIZE,
                    .kernel_log_level = VERIFIER_LOG_LEVEL_CONCISE);
        obj = bpf_object__open_file("malicious_terminate.kern.o", &open_opts);
    } else {
        obj = bpf_object__open_file("malicious_terminate.kern.o", NULL);
    }
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        goto err;
    }

    prog = bpf_object__find_program_by_name(obj, "malicious_terminate");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        goto err;
    }

    if (enable_verifier_logs) {
        if (bpf_program__set_log_level(prog, VERIFIER_LOG_LEVEL_CONCISE) != 0) {
            fprintf(stderr, "Failed to set verifier log level\n");
            goto err;
        }
        if (bpf_program__set_log_buf(prog, prog_log_buf, VERIFIER_LOG_BUF_SIZE) != 0) {
            fprintf(stderr, "Failed to set verifier log buffer\n");
            goto err;
        }
    }

    load_err = bpf_object__load(obj);
    if (load_err) {
        if (enable_verifier_logs && load_err == -ENOSPC) {
            fprintf(stderr,
                    "WARNING: verifier log exceeded %u bytes; retrying load without verifier logs\n",
                    VERIFIER_LOG_BUF_SIZE);
            bpf_object__close(obj);
            obj = NULL;
            free(kernel_log_buf);
            kernel_log_buf = NULL;
            free(prog_log_buf);
            prog_log_buf = NULL;
            enable_verifier_logs = 0;
            retried_without_logs = 1;
            goto open_obj;
        }
        dump_kernel_log("per-program verifier log", prog_log_buf);
        dump_kernel_log("object-level kernel log", kernel_log_buf);
        dump_dmesg_since(dmesg_since);
        fprintf(stderr, "Failed to load BPF object\n");
        goto err;
    }
    if (retried_without_logs) {
        fprintf(stderr,
                "WARNING: continuing without verifier logs after debug log truncation\n");
    }
    dump_kernel_log("per-program verifier log", prog_log_buf);
    dump_kernel_log("object-level kernel log", kernel_log_buf);

    link = bpf_program__attach_tracepoint(prog, category, event);
    link_err = libbpf_get_error(link);
    if (link_err) {
        fprintf(stderr, "Failed to attach tracepoint %s:%s\n", category, event);
        link = NULL;
        goto err;
    }
    dump_dmesg_since(dmesg_since);

    ctl_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
    if (ctl_fd < 0) {
        fprintf(stderr, "Failed to find control_map\n");
        goto err;
    }

    term_stats_fd = bpf_object__find_map_fd_by_name(obj, "termination_stats_map");
    if (term_stats_fd < 0) {
        fprintf(stderr, "Failed to find termination_stats_map\n");
        goto err;
    }

    session->prog_fd = bpf_program__fd(prog);
    if (session->prog_fd < 0 || get_prog_id(session->prog_fd, &session->prog_id) != 0) {
        fprintf(stderr, "Failed to read loaded program ID\n");
        goto err;
    }

    session->obj = obj;
    session->link = link;
    session->ctl_fd = ctl_fd;
    session->term_stats_fd = term_stats_fd;
    session->kernel_log_buf = kernel_log_buf;
    session->prog_log_buf = prog_log_buf;
    return 0;

err:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    free(kernel_log_buf);
    free(prog_log_buf);
    return -1;
}

static int start_redis_server(void)
{
    char db_path[256];
    char port_buf[32];
    int status;
    pid_t wait_rc;

    snprintf(db_path, sizeof(db_path), "%s/%s", g_redis_dir, g_redis_dbfilename);
    unlink(db_path);
    snprintf(port_buf, sizeof(port_buf), "%u", g_redis_port);

    char *argv[] = {
        "taskset", "-c", "0-15:2",
        "redis-server", "--bind", g_redis_host, "--port", port_buf,
        "--io-threads", "8", "--protected-mode", "no",
        "--save", "",
        "--appendonly", "no",
        "--dir", (char *)g_redis_dir,
        "--dbfilename", (char *)g_redis_dbfilename,
        "--loglevel", "warning",
        "--logfile", "/tmp/figure3_redis.log",
        NULL
    };
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    g_redis_pid = pid;
    sleep(1);
    wait_rc = waitpid(pid, &status, WNOHANG);
    if (wait_rc == pid) {
        g_redis_pid = -1;
        fprintf(stderr,
                "redis-server failed to stay up for %s:%u; check /tmp/figure3_redis.log\n",
                g_redis_host, g_redis_port);
        return -1;
    }
    printf("redis-server started (pid %d, persistence disabled, %s:%u)\n",
           pid, g_redis_host, g_redis_port);
    return 0;
}

static void stop_redis_server(void)
{
    if (g_redis_pid > 0) {
        printf("Stopping redis-server (pid %d)...\n", g_redis_pid);
        kill(g_redis_pid, SIGTERM);
        sleep(1);
        kill(g_redis_pid, SIGKILL);
        g_redis_pid = -1;
    }
    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path), "%s/%s", g_redis_dir, g_redis_dbfilename);
        unlink(db_path);
    }
}

static int run_memtier_ssh_json(char **out_json, unsigned int test_time)
{
    unsigned int remote_timeout = test_time + 20;
    char cmd[1536];
    snprintf(cmd, sizeof(cmd),
             "su - rosa -c 'ssh -o BatchMode=yes -o ConnectTimeout=5 "
             "-o ServerAliveInterval=5 -o ServerAliveCountMax=3 %s "
             "\"timeout %u memtier_benchmark --server=%s --port=%u "
             "--protocol=redis --clients=128 --threads=32 --test-time=%u "
             "--json-out-file results.json >/tmp/figure3_memtier.log 2>&1; "
             "rc=$?; tail -5 /tmp/figure3_memtier.log 2>/dev/null || true; "
             "test -f results.json && cat results.json; exit $rc\"'",
             g_ssh_target, remote_timeout, g_redis_host, g_redis_port, test_time);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        pclose(fp);
        return -1;
    }

    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *next = realloc(buf, cap);
            if (!next) {
                free(buf);
                pclose(fp);
                return -1;
            }
            buf = next;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    int status = pclose(fp);
    if (status != 0) {
        if (buf[0])
            fprintf(stderr, "%s\n", buf);
        fprintf(stderr,
                "memtier command via %s failed for %s:%u (status=%d)\n",
                g_ssh_target, g_redis_host, g_redis_port, status);
        free(buf);
        return -1;
    }
    *out_json = buf;
    return 0;
}

static const char *find_totals_block(const char *json)
{
    const char *p = strstr(json, "\"Totals\"");
    return p ? p : json;
}

static int extract_metric(const char *json, const char *key, double *out)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p)
        return -1;
    p = strchr(p, ':');
    if (!p)
        return -1;
    p++;
    *out = strtod(p, NULL);
    return 0;
}

static void memtier_stats_add(struct memtier_stats *dst, const struct memtier_stats *src)
{
    dst->ops_sec += src->ops_sec;
    dst->avg_latency_ms += src->avg_latency_ms;
    dst->max_latency_ms += src->max_latency_ms;
    dst->p99_latency_ms += src->p99_latency_ms;
    dst->p999_latency_ms += src->p999_latency_ms;
}

static void memtier_stats_div(struct memtier_stats *stats, double divisor)
{
    stats->ops_sec /= divisor;
    stats->avg_latency_ms /= divisor;
    stats->max_latency_ms /= divisor;
    stats->p99_latency_ms /= divisor;
    stats->p999_latency_ms /= divisor;
}

static int write_raw_json(const char *path, const char *json)
{
    FILE *raw_fp = fopen(path, "w");
    if (!raw_fp)
        return -1;
    fprintf(raw_fp, "%s", json);
    fclose(raw_fp);
    return 0;
}

static int append_raw_json_archive(const char *path, const char *phase,
                                   unsigned int work_iters, unsigned int run_idx,
                                   unsigned int runs, const char *json)
{
    char archive_path[1024];
    FILE *archive_fp;

    snprintf(archive_path, sizeof(archive_path), "%s.archive", path);
    archive_fp = fopen(archive_path, "a");
    if (!archive_fp)
        return -1;

    fprintf(archive_fp, "=== phase=%s work_iters=%u run=%u/%u ===\n",
            phase ? phase : "unknown", work_iters, run_idx, runs);
    fprintf(archive_fp, "%s\n\n", json);
    fclose(archive_fp);
    return 0;
}

static int parse_memtier_stats(const char *json, struct memtier_stats *stats)
{
    const char *totals = find_totals_block(json);
    const char *percentiles;

    memset(stats, 0, sizeof(*stats));

    if (extract_metric(totals, "Ops/sec", &stats->ops_sec) != 0 ||
        extract_metric(totals, "Average Latency", &stats->avg_latency_ms) != 0) {
        return -1;
    }

    if (extract_metric(totals, "Max Latency", &stats->max_latency_ms) != 0) {
        fprintf(stderr, "WARNING: Max Latency not found, falling back to Average Latency\n");
        stats->max_latency_ms = stats->avg_latency_ms;
    }

    percentiles = strstr(totals, "\"Percentile Latencies\"");
    if (percentiles) {
        if (extract_metric(percentiles, "p99.00", &stats->p99_latency_ms) != 0)
            stats->p99_latency_ms = stats->max_latency_ms;
        if (extract_metric(percentiles, "p99.90", &stats->p999_latency_ms) != 0)
            stats->p999_latency_ms = stats->max_latency_ms;
    } else {
        stats->p99_latency_ms = stats->max_latency_ms;
        stats->p999_latency_ms = stats->max_latency_ms;
    }

    return 0;
}

#define MAX_RUNS 32

static double compute_std(const double *vals, unsigned int n, double mean)
{
    if (n < 2)
        return 0.0;
    double sum_sq = 0.0;
    for (unsigned int i = 0; i < n; i++) {
        double d = vals[i] - mean;
        sum_sq += d * d;
    }
    return (sum_sq / (double)(n - 1)) > 0 ? sqrt(sum_sq / (double)(n - 1)) : 0.0;
}

static __u32 configured_insn_count_from_work_iters(__u32 work_iters)
{
    /*
     * This intentionally models the no-termination work path so the x-axis
     * remains the requested workload size, not the truncated executed work
     * after budgeted termination.
     */
    return 17 + 26 * (work_iters / 128);
}

static double time_limit_us_from_ns(__u64 time_limit_ns)
{
    return (double)time_limit_ns / 1000.0;
}

static void write_csv_header(FILE *csv,
                             const struct memtier_stats *baseline_stats,
                             unsigned int baseline_completed_runs,
                             unsigned int runs)
{
    fprintf(csv, "exp_mode,work_iters,configured_insn_count,time_limit_ns,"
            "time_limit_us,run_number,ops_sec,avg_latency_ms,max_latency_ms,"
            "p99_latency_ms,p999_latency_ms,baseline_ops_sec,"
            "baseline_avg_latency_ms,baseline_p99_latency_ms,"
            "baseline_max_latency_ms,avg_bpf_runtime_ns,bpf_invocations,"
            "termination_hits,avg_elapsed_ns_before_termination,"
            "avg_completed_work_iters_before_termination\n");
    if (baseline_stats->ops_sec > 0) {
        fprintf(csv, "# Baseline (no BPF, avg of %u/%u runs): %.2f ops/sec, "
                "%.2f ms avg, %.2f ms p99, %.2f ms max latency\n",
                baseline_completed_runs, runs, baseline_stats->ops_sec,
                baseline_stats->avg_latency_ms, baseline_stats->p99_latency_ms,
                baseline_stats->max_latency_ms);
    }
}

static void write_csv_rows(FILE *csv,
                           enum experiment_mode exp_mode,
                           const struct control_args *ctl,
                           const struct memtier_stats *per_run,
                           unsigned int completed_runs,
                           const struct memtier_stats *baseline_stats,
                           double avg_bpf_ns,
                           __u64 bpf_calls,
                           const struct termination_stats_summary *term_summary)
{
    __u32 configured_insn_count = configured_insn_count_from_work_iters(ctl->work_iters);
    double time_limit_us = time_limit_us_from_ns(ctl->time_limit_ns);

    for (unsigned int r = 0; r < completed_runs; r++) {
        fprintf(csv,
                "%s,%u,%u,%llu,%.3f,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
                "%.2f,%.2f,%.2f,%llu,%llu,%.2f,%.2f\n",
                exp_mode_csv_name(exp_mode),
                ctl->work_iters,
                configured_insn_count,
                (unsigned long long)ctl->time_limit_ns,
                time_limit_us,
                r + 1,
                per_run[r].ops_sec,
                per_run[r].avg_latency_ms,
                per_run[r].max_latency_ms,
                per_run[r].p99_latency_ms,
                per_run[r].p999_latency_ms,
                baseline_stats->ops_sec,
                baseline_stats->avg_latency_ms,
                baseline_stats->p99_latency_ms,
                baseline_stats->max_latency_ms,
                avg_bpf_ns,
                (unsigned long long)bpf_calls,
                (unsigned long long)(term_summary ? term_summary->hits : 0),
                term_summary ? term_summary->avg_elapsed_ns_before_termination : 0.0,
                term_summary ? term_summary->avg_completed_work_iters_before_termination : 0.0);
    }
}

static int run_memtier_averaged(unsigned int test_time, unsigned int runs,
                                const char *raw_json_path, int save_raw_json,
                                const char *phase, unsigned int work_iters,
                                struct memtier_stats *avg_out,
                                unsigned int *completed_runs_out,
                                double *max_latency_std_out,
                                struct memtier_stats *per_run_out)
{
    struct memtier_stats sum = {0};
    double max_lat_vals[MAX_RUNS];
    unsigned int completed = 0;

    if (runs > MAX_RUNS)
        runs = MAX_RUNS;

    for (unsigned int run = 0; run < runs; run++) {
        char *json = NULL;
        struct memtier_stats one = {0};

        if (run_memtier_ssh_json(&json, test_time) != 0 || !json) {
            fprintf(stderr, "WARNING: memtier run %u/%u failed\n", run + 1, runs);
            free(json);
            continue;
        }

        if (save_raw_json && raw_json_path) {
            if (write_raw_json(raw_json_path, json) != 0)
                fprintf(stderr, "WARNING: failed to write raw JSON snapshot to %s\n",
                        raw_json_path);
            if (append_raw_json_archive(raw_json_path, phase, work_iters, run + 1, runs,
                                        json) != 0) {
                fprintf(stderr, "WARNING: failed to append raw JSON archive %s.archive\n",
                        raw_json_path);
            }
        }

        if (parse_memtier_stats(json, &one) != 0) {
            fprintf(stderr, "WARNING: failed to parse memtier stats on run %u/%u\n",
                    run + 1, runs);
            free(json);
            continue;
        }

        if (per_run_out)
            per_run_out[completed] = one;
        memtier_stats_add(&sum, &one);
        max_lat_vals[completed] = one.max_latency_ms;
        completed++;
        free(json);
    }

    if (completed == 0)
        return -1;

    memtier_stats_div(&sum, (double)completed);
    *avg_out = sum;
    if (completed_runs_out)
        *completed_runs_out = completed;
    if (max_latency_std_out)
        *max_latency_std_out = compute_std(max_lat_vals, completed, sum.max_latency_ms);
    return 0;
}

static int run_sweep(const char *category, const char *event,
                     enum experiment_mode exp_mode,
                     __u64 time_limit_ns,
                     unsigned int max_val, unsigned int step,
                     unsigned int runs, unsigned int test_time,
                     const char *csv_path, const char *raw_json_path,
                     const struct memtier_stats *baseline_stats,
                     unsigned int baseline_completed_runs,
                     int verify_reload)
{
    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        fprintf(stderr, "Failed to open CSV: %s\n", csv_path);
        return -1;
    }
    write_csv_header(csv, baseline_stats, baseline_completed_runs, runs);

    unsigned int total_iters = (max_val / step) + 1;
    unsigned int current = 0;
    __u32 prev_prog_id = 0;
    __u32 key = 0;
    struct control_args ctl = {
        .mode = exp_mode,
        .time_limit_ns = time_limit_ns,
    };
    int rc = 0;

    for (unsigned int val = 0; val <= max_val; val += step) {
        struct bpf_session session;
        struct memtier_stats point_stats = {0};
        struct termination_stats_summary term_summary = {};
        unsigned int point_completed_runs = 0;
        __u32 closed_prog_id;

        current++;
        ctl.work_iters = val;
        printf("[%u/%u] mode=%s work_iters=%u",
               current, total_iters, exp_mode_cli_name(exp_mode),
               ctl.work_iters);
        if (exp_mode == EXP_MODE_TERMINATION_BUDGETED)
            printf(" time_limit=%.3f us", time_limit_us_from_ns(ctl.time_limit_ns));
        printf(" (%u run(s))...\n", runs);

        if (bpf_session_open(&session, category, event) != 0) {
            fprintf(stderr, "Failed to prepare BPF session for work_iters=%u\n", val);
            rc = -1;
            break;
        }
        if (verify_reload && prev_prog_id && session.prog_id == prev_prog_id) {
            fprintf(stderr, "Reload verification failed: program ID reused (%u)\n",
                    session.prog_id);
            bpf_session_close(&session);
            rc = -1;
            break;
        }

        if (bpf_map_update_elem(session.ctl_fd, &key, &ctl, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update control_map for work_iters=%u: %s\n",
                    ctl.work_iters, strerror(errno));
            bpf_session_close(&session);
            rc = -1;
            break;
        }
        if (zero_termination_stats(session.term_stats_fd) != 0) {
            fprintf(stderr, "Failed to reset termination_stats_map for work_iters=%u: %s\n",
                    ctl.work_iters, strerror(errno));
            bpf_session_close(&session);
            rc = -1;
            break;
        }

        struct prog_runtime_stats rt_before = {}, rt_after = {};
        struct memtier_stats per_run[MAX_RUNS];
        get_prog_runtime_stats(session.prog_fd, &rt_before);

        if (run_memtier_averaged(test_time, runs, raw_json_path, 1,
                                 exp_mode_csv_name(exp_mode),
                                 ctl.work_iters, &point_stats,
                                 &point_completed_runs, NULL, per_run) != 0) {
            fprintf(stderr, "memtier failed for work_iters=%u across all %u run(s)\n",
                    ctl.work_iters, runs);
            bpf_session_close(&session);
            rc = -1;
            break;
        }

        get_prog_runtime_stats(session.prog_fd, &rt_after);
        if (read_termination_stats_summary(session.term_stats_fd, &term_summary) != 0) {
            fprintf(stderr, "Failed to read termination_stats_map for work_iters=%u: %s\n",
                    ctl.work_iters, strerror(errno));
            bpf_session_close(&session);
            rc = -1;
            break;
        }
        __u64 bpf_total_ns = rt_after.run_time_ns - rt_before.run_time_ns;
        __u64 bpf_calls = rt_after.run_cnt - rt_before.run_cnt;
        double avg_bpf_ns = bpf_calls > 0 ? (double)bpf_total_ns / bpf_calls : 0;

        closed_prog_id = session.prog_id;
        bpf_session_close(&session);
        if (verify_reload) {
            int gone = verify_prog_gone(closed_prog_id);
            if (gone > 0) {
                fprintf(stderr, "Reload verification failed: old program ID %u still exists\n",
                        closed_prog_id);
                rc = -1;
                break;
            }
            if (gone < 0)
                fprintf(stderr, "WARNING: could not verify old program ID %u cleanup\n",
                        closed_prog_id);
            prev_prog_id = closed_prog_id;
        }

        write_csv_rows(csv, exp_mode, &ctl, per_run, point_completed_runs,
                       baseline_stats, avg_bpf_ns, bpf_calls, &term_summary);
        fflush(csv);
        double loss_pct = baseline_stats->ops_sec > 0
            ? (1.0 - point_stats.ops_sec / baseline_stats->ops_sec) * 100 : 0;
        printf("  -> Ops/sec: %.2f, Max latency: %.2f ms, p99: %.2f ms, "
               "Loss: %.1f%%, Avg BPF: %.0f ns (%llu calls, %u/%u runs), "
               "Termination hits: %llu, Avg elapsed: %.0f ns, Avg completed work: %.1f iters\n",
               point_stats.ops_sec, point_stats.max_latency_ms,
               point_stats.p99_latency_ms, loss_pct, avg_bpf_ns,
               (unsigned long long)bpf_calls, point_completed_runs, runs,
               (unsigned long long)term_summary.hits,
               term_summary.avg_elapsed_ns_before_termination,
               term_summary.avg_completed_work_iters_before_termination);
    }

    fclose(csv);
    printf("Results saved to %s\n", csv_path);
    return rc;
}

static void derive_companion_csv_path(const char *base_path, const char *suffix,
                                      char *out, size_t out_sz)
{
    const char *dot = strrchr(base_path, '.');
    if (dot) {
        size_t prefix_len = (size_t)(dot - base_path);
        snprintf(out, out_sz, "%.*s-%s%s", (int)prefix_len, base_path, suffix, dot);
    } else {
        snprintf(out, out_sz, "%s-%s", base_path, suffix);
    }
}

int main(int argc, char **argv)
{
    const char *tp = NULL;
    struct control_args ctl = {
        .work_iters = 1,
        .mode = EXP_MODE_NO_TERMINATION,
        .time_limit_ns = 0,
    };
    enum experiment_mode exp_mode = EXP_MODE_NO_TERMINATION;
    enum experiment_mode termination_mode = EXP_MODE_TERMINATION_IMMEDIATE;
    enum termination_style term_style = TERM_STYLE_IMMEDIATE;
    int run_both = 0;
    const char *csv_path = "figure3_results.csv";
    const char *raw_json_path = "memtier_raw.json";
    int have_max = 0;
    int have_time_limit_us = 0;
    unsigned int max_val = VERIFIER_SAFE_MAX_WORK_ITERS;
    unsigned int step = 1;
    unsigned int runs = 3;  // default: average 3 memtier runs per point
    unsigned int test_time = 120;  // default: 120 seconds
    int start_redis = 1;  // default: yes
    int ssh_memtier = 1;  // default: yes
    int verify_reload = 1;
    double time_limit_us = DEFAULT_TIME_LIMIT_US;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tracepoint") && i + 1 < argc) {
            tp = argv[++i];
        } else if (!strcmp(argv[i], "--work-iters") && i + 1 < argc) {
            ctl.work_iters = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--die-after") && i + 1 < argc) {
            ctl.work_iters = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--exp-mode") && i + 1 < argc) {
            if (parse_exp_mode(argv[++i], &exp_mode, &run_both) != 0) {
                fprintf(stderr, "Invalid --exp-mode (use no-termination|termination|both)\n");
                return 1;
            }
        } else if (!strcmp(argv[i], "--termination-style") && i + 1 < argc) {
            if (parse_termination_style(argv[++i], &term_style) != 0) {
                fprintf(stderr, "Invalid --termination-style (use immediate|budgeted)\n");
                return 1;
            }
        } else if (!strcmp(argv[i], "--time-limit-us") && i + 1 < argc) {
            char *endptr = NULL;

            errno = 0;
            time_limit_us = strtod(argv[++i], &endptr);
            if (errno || !endptr || *endptr != '\0' || time_limit_us <= 0.0) {
                fprintf(stderr, "Invalid --time-limit-us value\n");
                return 1;
            }
            have_time_limit_us = 1;
        } else if (!strcmp(argv[i], "--max")) {
            have_max = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                max_val = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--step") && i + 1 < argc) {
            step = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--runs") && i + 1 < argc) {
            runs = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!strcmp(argv[i], "--test-time") && i + 1 < argc) {
            test_time = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--raw-json") && i + 1 < argc) {
            raw_json_path = argv[++i];
        } else if (!strcmp(argv[i], "--redis-host") && i + 1 < argc) {
            snprintf(g_redis_host, sizeof(g_redis_host), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--redis-port") && i + 1 < argc) {
            g_redis_port = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--ssh-target") && i + 1 < argc) {
            snprintf(g_ssh_target, sizeof(g_ssh_target), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--no-redis")) {
            start_redis = 0;
        } else if (!strcmp(argv[i], "--no-memtier")) {
            ssh_memtier = 0;
        } else if (!strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "--no-verify-reload")) {
            verify_reload = 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!tp) {
        usage(argv[0]);
        return 1;
    }
    if (runs == 0) {
        fprintf(stderr, "--runs must be > 0\n");
        return 1;
    }
    if (g_redis_port == 0) {
        fprintf(stderr, "--redis-port must be > 0\n");
        return 1;
    }
    if (ctl.work_iters > VERIFIER_SAFE_MAX_WORK_ITERS) {
        fprintf(stderr, "--work-iters %u exceeds verifier-safe cap (%u), clamping\n",
                ctl.work_iters, VERIFIER_SAFE_MAX_WORK_ITERS);
        ctl.work_iters = VERIFIER_SAFE_MAX_WORK_ITERS;
    }
    if (have_max && max_val > VERIFIER_SAFE_MAX_WORK_ITERS) {
        fprintf(stderr, "--max %u exceeds verifier-safe cap (%u), clamping\n",
                max_val, VERIFIER_SAFE_MAX_WORK_ITERS);
        max_val = VERIFIER_SAFE_MAX_WORK_ITERS;
    }
    if (run_both && !have_max) {
        fprintf(stderr, "--exp-mode both requires --max/--step sweep mode\n");
        return 1;
    }
    if (have_time_limit_us && term_style != TERM_STYLE_BUDGETED) {
        fprintf(stderr, "--time-limit-us requires --termination-style budgeted\n");
        return 1;
    }
    if (term_style == TERM_STYLE_BUDGETED) {
        if (!have_time_limit_us) {
            fprintf(stderr, "--termination-style budgeted requires --time-limit-us\n");
            return 1;
        }
        if (!run_both && exp_mode == EXP_MODE_NO_TERMINATION) {
            fprintf(stderr, "--termination-style budgeted requires --exp-mode termination or both\n");
            return 1;
        }
        ctl.time_limit_ns = (__u64)llround(time_limit_us * 1000.0);
        termination_mode = EXP_MODE_TERMINATION_BUDGETED;
    }
    if (exp_mode == EXP_MODE_TERMINATION_IMMEDIATE)
        exp_mode = termination_mode;
    ctl.mode = exp_mode;

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must run as root\n");
        return 1;
    }

    if (ssh_memtier) {
        if (ensure_bpf_stats_enabled(&g_bpf_stats_state) != 0)
            return 1;
        atexit(restore_bpf_stats_enabled_atexit);
    }

    if (start_redis) {
        if (start_redis_server() != 0)
            return 1;
    } else {
        printf("Redis command (optional):\n");
        printf("  taskset -c 0-15:2 redis-server --bind %s --port %u "
               "--io-threads 8 --protected-mode no\n",
               g_redis_host, g_redis_port);
    }

    if (!ssh_memtier) {
        printf("Memtier command (run on %s):\n", g_ssh_target);
        printf("  memtier_benchmark --server=%s --port=%u "
               "--protocol=redis --clients=128 --threads=32 --test-time=%u "
               "--json-out-file results.json\n", g_redis_host, g_redis_port,
               test_time);
    }

    // Measure baseline throughput (no BPF program attached)
    struct memtier_stats baseline_stats = {0};
    unsigned int baseline_completed_runs = 0;
    if (ssh_memtier) {
        printf("\n=== Measuring baseline (no BPF) ===\n");
        printf("Running memtier benchmark on %s against %s:%u (%u run(s), ~%u seconds each)...\n",
               g_ssh_target, g_redis_host, g_redis_port, runs, test_time);
        fflush(stdout);
        if (run_memtier_averaged(test_time, runs, raw_json_path, 1, "baseline", 0,
                                 &baseline_stats,
                                 &baseline_completed_runs, NULL, NULL) != 0) {
            fprintf(stderr, "Baseline memtier run failed across all %u run(s)\n", runs);
            memset(&baseline_stats, 0, sizeof(baseline_stats));
        } else {
            printf("Baseline (avg of %u/%u run(s)): %.2f ops/sec, %.2f ms avg, %.2f ms p99, %.2f ms max latency\n\n",
                   baseline_completed_runs, runs, baseline_stats.ops_sec,
                   baseline_stats.avg_latency_ms, baseline_stats.p99_latency_ms,
                   baseline_stats.max_latency_ms);
        }
    }

    char category[128], event[128];
    if (split_tracepoint(tp, category, sizeof(category), event, sizeof(event)) != 0) {
        fprintf(stderr, "Invalid tracepoint format (use CATEGORY:EVENT)\n");
        return 1;
    }

    /*
     * Make logging deterministic across runs even if user's shell has
     * LIBBPF_LOG_LEVEL exported from prior experiments.
     */
    setenv("LIBBPF_LOG_LEVEL", verbose ? "debug" : "warn", 1);
    libbpf_set_print(libbpf_print_fn);

    __u32 key = 0;
    if (have_max && step == 0) {
        fprintf(stderr, "--step must be > 0\n");
        return 1;
    }
    if (have_max && !ssh_memtier) {
        fprintf(stderr, "--no-memtier cannot be used with --max/--step\n");
        return 1;
    }

    if (have_max) {
        if (run_both) {
            char term_csv[1024];
            const char *term_suffix = termination_mode == EXP_MODE_TERMINATION_BUDGETED
                ? "budget" : "term";
            derive_companion_csv_path(csv_path, term_suffix, term_csv, sizeof(term_csv));

            printf("\n========== Phase 1/2: no-termination sweep ==========\n");
            if (run_sweep(category, event, EXP_MODE_NO_TERMINATION,
                          0,
                          max_val, step, runs, test_time,
                          csv_path, raw_json_path,
                          &baseline_stats, baseline_completed_runs,
                          verify_reload) != 0)
                fprintf(stderr, "WARNING: no-termination sweep had errors\n");

            printf("\n========== Phase 2/2: termination (%s) sweep ==========\n",
                   termination_style_name(term_style));
            if (run_sweep(category, event, termination_mode,
                          ctl.time_limit_ns,
                          max_val, step, runs, test_time,
                          term_csv, raw_json_path,
                          &baseline_stats, baseline_completed_runs,
                          verify_reload) != 0)
                fprintf(stderr, "WARNING: termination sweep had errors\n");

            printf("\nNo-termination results: %s\n", csv_path);
            printf("Termination results:    %s\n", term_csv);
        } else {
            if (run_sweep(category, event, exp_mode,
                          ctl.time_limit_ns,
                          max_val, step, runs, test_time,
                          csv_path, raw_json_path,
                          &baseline_stats, baseline_completed_runs,
                          verify_reload) != 0)
                fprintf(stderr, "WARNING: sweep had errors\n");
        }
        printf("Raw memtier snapshot: %s\n", raw_json_path);
        printf("Raw memtier archive: %s.archive\n", raw_json_path);
        stop_redis_server();
        return 0;
    }

    FILE *csv = NULL;
    if (ssh_memtier) {
        csv = fopen(csv_path, "w");
        if (!csv) {
            fprintf(stderr, "Failed to open CSV: %s\n", csv_path);
            return 1;
        }
        write_csv_header(csv, &baseline_stats, baseline_completed_runs, runs);
    }

    struct bpf_session session;
    ctl.mode = exp_mode;
    if (bpf_session_open(&session, category, event) != 0) {
        if (csv)
            fclose(csv);
        stop_redis_server();
        return 1;
    }

    printf("Attached to %s:%s (mode=%s, work_iters=%u",
           category, event, exp_mode_cli_name(exp_mode), ctl.work_iters);
    if (ctl.mode == EXP_MODE_TERMINATION_BUDGETED)
        printf(", time_limit=%.3f us", time_limit_us_from_ns(ctl.time_limit_ns));
    printf(")\n");

    if (bpf_map_update_elem(session.ctl_fd, &key, &ctl, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update control_map: %s\n", strerror(errno));
        if (csv)
            fclose(csv);
        bpf_session_close(&session);
        stop_redis_server();
        return 1;
    }
    if (zero_termination_stats(session.term_stats_fd) != 0) {
        fprintf(stderr, "Failed to reset termination_stats_map: %s\n", strerror(errno));
        if (csv)
            fclose(csv);
        bpf_session_close(&session);
        stop_redis_server();
        return 1;
    }

    if (ssh_memtier) {
        struct memtier_stats point_stats = {0};
        struct termination_stats_summary term_summary = {};
        unsigned int point_completed_runs = 0;
        printf("Running memtier benchmark on %s against %s:%u (%u run(s), ~%u seconds each)...\n",
               g_ssh_target, g_redis_host, g_redis_port, runs, test_time);
        fflush(stdout);

        struct prog_runtime_stats rt_before = {}, rt_after = {};
        struct memtier_stats per_run[MAX_RUNS];
        get_prog_runtime_stats(session.prog_fd, &rt_before);

        if (run_memtier_averaged(test_time, runs, raw_json_path, 1,
                                 exp_mode_csv_name(exp_mode),
                                 ctl.work_iters, &point_stats,
                                 &point_completed_runs, NULL, per_run) != 0) {
            fprintf(stderr, "memtier failed across all %u run(s)\n", runs);
        } else if (csv) {
            get_prog_runtime_stats(session.prog_fd, &rt_after);
            if (read_termination_stats_summary(session.term_stats_fd, &term_summary) != 0) {
                fprintf(stderr, "Failed to read termination_stats_map: %s\n", strerror(errno));
                if (csv)
                    fclose(csv);
                stop_redis_server();
                bpf_session_close(&session);
                return 1;
            }
            __u64 bpf_total_ns = rt_after.run_time_ns - rt_before.run_time_ns;
            __u64 bpf_calls = rt_after.run_cnt - rt_before.run_cnt;
            double avg_bpf_ns = bpf_calls > 0 ? (double)bpf_total_ns / bpf_calls : 0;

            write_csv_rows(csv, exp_mode, &ctl, per_run, point_completed_runs,
                           &baseline_stats, avg_bpf_ns, bpf_calls, &term_summary);
            fflush(csv);
            double loss_pct = baseline_stats.ops_sec > 0 ? (1.0 - point_stats.ops_sec / baseline_stats.ops_sec) * 100 : 0;
            printf("Ops/sec: %.2f, Max latency: %.2f ms, p99: %.2f ms, Loss: %.1f%%, Avg BPF: %.0f ns (%llu calls, %u/%u runs), Termination hits: %llu, Avg elapsed: %.0f ns, Avg completed work: %.1f iters\n",
                   point_stats.ops_sec, point_stats.max_latency_ms,
                   point_stats.p99_latency_ms, loss_pct, avg_bpf_ns,
                   (unsigned long long)bpf_calls, point_completed_runs, runs,
                   (unsigned long long)term_summary.hits,
                   term_summary.avg_elapsed_ns_before_termination,
                   term_summary.avg_completed_work_iters_before_termination);
            printf("Raw memtier snapshot: %s\n", raw_json_path);
            printf("Raw memtier archive: %s.archive\n", raw_json_path);
        }
        if (csv)
            fclose(csv);
        printf("Results saved to %s\n", csv_path);
        stop_redis_server();
        bpf_session_close(&session);
        return 0;
    }

    printf("Press Ctrl-C to detach\n");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    while (g_running)
        sleep(1);

    stop_redis_server();
    bpf_session_close(&session);
    return 0;
}
