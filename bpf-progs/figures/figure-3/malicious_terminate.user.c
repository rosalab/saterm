#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct control_args {
    __u32 die_after;
};

static volatile sig_atomic_t g_running = 1;
static pid_t g_redis_pid = -1;

static void on_signal(int signo)
{
    (void)signo;
    g_running = 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s --tracepoint CATEGORY:EVENT [options]\n", prog);
    printf("Options:\n");
    printf("  --die-after N       iterations before calling bpf_die (default 1, 0=immediate)\n");
    printf("  --max N             iterate die_after from 0..N (inclusive)\n");
    printf("  --step N            step size for --max iterations (default 1)\n");
    printf("  --test-time N       memtier test duration in seconds (default 120)\n");
    printf("  --csv PATH          write results to CSV (default figure3_results.csv)\n");
    printf("  --raw-json PATH     save raw memtier JSON output (default memtier_raw.json)\n");
    printf("  --no-redis          don't start redis-server (default: start)\n");
    printf("  --no-memtier        don't run memtier benchmark (default: run)\n");
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

static int start_redis_server(void)
{
    char *argv[] = {
        "taskset", "-c", "0-15:2",
        "redis-server", "--bind", "192.168.10.1", "--port", "11212",
        "--io-threads", "8", "--protected-mode", "no",
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
    printf("redis-server started (pid %d)\n", pid);
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
}

static int run_memtier_ssh_json(char **out_json, unsigned int test_time)
{
    char memtier_cmd[512];
    snprintf(memtier_cmd, sizeof(memtier_cmd),
        "memtier_benchmark --server=192.168.10.1 --port=11212 "
        "--protocol=redis --clients=128 --threads=32 --test-time=%u "
        "--json-out-file results.json 2>&1", test_time);
    char cmd[768];
    snprintf(cmd, sizeof(cmd),
             "su - rosa -c \"ssh deimos-vm '%s | tail -5; cat results.json'\"", memtier_cmd);

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
    pclose(fp);
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

int main(int argc, char **argv)
{
    const char *tp = NULL;
    struct control_args ctl = {
        .die_after = 1,
    };
    const char *csv_path = "figure3_results.csv";
    const char *raw_json_path = "memtier_raw.json";
    int have_max = 0;
    unsigned int max_val = 0;
    unsigned int step = 1;
    unsigned int test_time = 120;  // default: 120 seconds
    int start_redis = 1;  // default: yes
    int ssh_memtier = 1;  // default: yes

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tracepoint") && i + 1 < argc) {
            tp = argv[++i];
        } else if (!strcmp(argv[i], "--die-after") && i + 1 < argc) {
            ctl.die_after = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--max") && i + 1 < argc) {
            have_max = 1;
            max_val = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--step") && i + 1 < argc) {
            step = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!strcmp(argv[i], "--test-time") && i + 1 < argc) {
            test_time = (unsigned int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--raw-json") && i + 1 < argc) {
            raw_json_path = argv[++i];
        } else if (!strcmp(argv[i], "--no-redis")) {
            start_redis = 0;
        } else if (!strcmp(argv[i], "--no-memtier")) {
            ssh_memtier = 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!tp) {
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must run as root\n");
        return 1;
    }

    if (start_redis) {
        if (start_redis_server() != 0)
            fprintf(stderr, "Failed to launch redis-server\n");
    } else {
        printf("Redis command (optional):\n");
        printf("  taskset -c 0-15:2 redis-server --bind 192.168.10.1 --port 11212 "
               "--io-threads 8 --protected-mode no\n");
    }

    if (!ssh_memtier) {
        printf("Memtier command (run on deimos-vm):\n");
        printf("  memtier_benchmark --server=192.168.10.1 --port=11212 "
               "--protocol=redis --clients=128 --threads=32 --test-time=%u "
               "--json-out-file results.json\n", test_time);
    }

    struct bpf_object *obj = bpf_object__open_file("malicious_terminate.kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "malicious_terminate");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        bpf_object__close(obj);
        return 1;
    }

    char category[128], event[128];
    if (split_tracepoint(tp, category, sizeof(category), event, sizeof(event)) != 0) {
        fprintf(stderr, "Invalid tracepoint format (use CATEGORY:EVENT)\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, event);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach tracepoint %s:%s\n", category, event);
        bpf_object__close(obj);
        return 1;
    }

    __u32 key = 0;
    int ctl_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
    if (ctl_fd < 0) {
        fprintf(stderr, "Failed to find control_map\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    if (have_max && step == 0) {
        fprintf(stderr, "--step must be > 0\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    if (have_max && !ssh_memtier) {
        fprintf(stderr, "--ssh-memtier is required when using --max/--step\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("Attached to %s:%s (die_after=%u)\n", category, event, ctl.die_after);

    FILE *csv = NULL;
    if (have_max || ssh_memtier) {
        csv = fopen(csv_path, "w");
        if (!csv) {
            fprintf(stderr, "Failed to open CSV: %s\n", csv_path);
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return 1;
        }
        fprintf(csv, "die_after,ops_sec,avg_latency_ms\n");
    }

    if (have_max) {
        unsigned int total_iters = (max_val + step - 1) / step;
        unsigned int current = 0;
        for (unsigned int val = 0; val < max_val; val += step) {
            current++;
            printf("[%u/%u] Running memtier with die_after=%u...\n", 
                   current, total_iters, val);
            
            ctl.die_after = val;
            bpf_map_update_elem(ctl_fd, &key, &ctl, BPF_ANY);

            char *json = NULL;
            if (run_memtier_ssh_json(&json, test_time) != 0 || !json) {
                fprintf(stderr, "memtier ssh command failed\n");
                free(json);
                break;
            }

            // Save raw JSON
            FILE *raw_fp = fopen(raw_json_path, "w");
            if (raw_fp) {
                fprintf(raw_fp, "%s", json);
                fclose(raw_fp);
            }

            const char *totals = find_totals_block(json);
            double ops = 0.0, avg_lat = 0.0;
            if (extract_metric(totals, "Ops/sec", &ops) != 0 ||
                extract_metric(totals, "Average Latency", &avg_lat) != 0) {
                fprintf(stderr, "Failed to parse memtier JSON metrics\n");
            }

            fprintf(csv, "%u,%.2f,%.2f\n", ctl.die_after, ops, avg_lat);
            fflush(csv);
            printf("  -> Ops/sec: %.2f, Avg latency: %.2f ms\n", ops, avg_lat);
            free(json);
        }
        if (csv)
            fclose(csv);
        printf("Results saved to %s\n", csv_path);
        stop_redis_server();
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 0;
    }

    bpf_map_update_elem(ctl_fd, &key, &ctl, BPF_ANY);

    if (ssh_memtier) {
        printf("Running memtier benchmark on deimos-vm (this takes ~%u seconds)...\n", test_time);
        fflush(stdout);
        char *json = NULL;
        if (run_memtier_ssh_json(&json, test_time) != 0 || !json) {
            fprintf(stderr, "memtier ssh command failed\n");
        } else {
            printf("Memtier benchmark completed, parsing results...\n");
            
            // Save raw JSON
            FILE *raw_fp = fopen(raw_json_path, "w");
            if (raw_fp) {
                fprintf(raw_fp, "%s", json);
                fclose(raw_fp);
                printf("Raw JSON saved to %s\n", raw_json_path);
            }
            
            const char *totals = find_totals_block(json);
            double ops = 0.0, avg_lat = 0.0;
            if (extract_metric(totals, "Ops/sec", &ops) != 0 ||
                extract_metric(totals, "Average Latency", &avg_lat) != 0) {
                fprintf(stderr, "Failed to parse memtier JSON metrics\n");
            } else if (csv) {
                fprintf(csv, "%u,%.2f,%.2f\n", ctl.die_after, ops, avg_lat);
                fflush(csv);
                printf("Ops/sec: %.2f, Avg latency: %.2f ms\n", ops, avg_lat);
            }
            free(json);
        }
        if (csv)
            fclose(csv);
        printf("Results saved to %s\n", csv_path);
        stop_redis_server();
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 0;
    }

    printf("Press Ctrl-C to detach\n");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    while (g_running)
        sleep(1);

    stop_redis_server();
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
