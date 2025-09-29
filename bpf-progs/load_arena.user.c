// load_arena.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>

static void die(const char *msg, int err) {
    fprintf(stderr, "%s: %s (%d)\n", msg, strerror(err > 0 ? err : -err), err);
    exit(1);
}

static int has_prefix(const char *s, const char *p) {
    size_t n = strlen(p);
    return strncmp(s, p, n) == 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_map *arena = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link **links = NULL;
    size_t n_links = 0, cap_links = 0;
    int err;

    // 1) Open object
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    obj = bpf_object__open_file("arena.kern.o", &open_opts);
    if (!obj) die("bpf_object__open_file failed", EINVAL);

    // 2) Find arena map and set user VA (map_extra) before load
    arena = bpf_object__find_map_by_name(obj, "arena");
    if (!arena) die("can't find map 'arena'", ENOENT);

    long page = sysconf(_SC_PAGESIZE);
    size_t pages = bpf_map__max_entries(arena); // ARENA max_entries = #pages
    size_t len = pages * (size_t)page;

    void *user_base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_base == MAP_FAILED) die("reserve mmap failed", errno);

    bpf_map__set_map_extra(arena, (unsigned long)user_base);

    // 3) Load maps + programs (verifier now knows the arena base)
    err = bpf_map__set_map_extra(arena, (unsigned long)user_base);

    // 3) Load maps + programs (verifier now knows the arena base)
    err = bpf_object__load(obj);
    if (err) die("bpf_object__load failed", err);

    // 4) Map arena at the exact promised address. Control protection via env.
    int arena_fd = bpf_map__fd(arena);
    int prot = PROT_READ | PROT_WRITE;          // default RW
    const char *prot_env = getenv("ARENA_PROT");
    if (prot_env && !strcasecmp(prot_env, "none")) prot = PROT_NONE;
    else if (prot_env && !strcasecmp(prot_env, "ro")) prot = PROT_READ;

    void *mapped = mmap(user_base, len, prot, MAP_SHARED | MAP_FIXED, arena_fd, 0);
    if (mapped == MAP_FAILED) die("MAP_FIXED mmap of arena failed", errno);

    // 5) Attach all programs based on their section
    links = calloc(8, sizeof(*links));
    cap_links = 8;
    if (!links) die("calloc", ENOMEM);

    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        struct bpf_link *link = NULL;

        if (!sec) continue;

        if (has_prefix(sec, "tracepoint/")) {
            // sec format: "tracepoint/<cat>/<name>"
            const char *cat = sec + strlen("tracepoint/");
            const char *slash = strchr(cat, '/');
            if (!slash) {
                fprintf(stderr, "WARN: bad tracepoint sec '%s'\n", sec);
                continue;
            }
            char category[128], event[128];
            size_t cat_len = (size_t)(slash - cat);
            if (cat_len >= sizeof(category)) { fprintf(stderr, "WARN: tp category too long\n"); continue; }
            memcpy(category, cat, cat_len);
            category[cat_len] = '\0';
            snprintf(event, sizeof(event), "%s", slash + 1);

            link = bpf_program__attach_tracepoint(prog, category, event);
            err = libbpf_get_error(link);
            if (err) die("attach tracepoint failed", err);

            printf("Attached TP %s:%s\n", category, event);

        } else if (has_prefix(sec, "kprobe/")) {
            // sec format: "kprobe/<symbol>"
            const char *sym = sec + strlen("kprobe/");
            link = bpf_program__attach_kprobe(prog, /*retprobe=*/false, sym);
            err = libbpf_get_error(link);
            if (err) die("attach kprobe failed", err);

            printf("Attached kprobe %s\n", sym);

        } else if (has_prefix(sec, "kretprobe/")) {
            const char *sym = sec + strlen("kretprobe/");
            link = bpf_program__attach_kprobe(prog, /*retprobe=*/true, sym);
            err = libbpf_get_error(link);
            if (err) die("attach kretprobe failed", err);

            printf("Attached kretprobe %s\n", sym);

        } else if (has_prefix(sec, "fentry/") || has_prefix(sec, "fexit/")) {
            // let libbpf auto-attach fentry/fexit
            link = bpf_program__attach(prog);
            err = libbpf_get_error(link);
            if (err) die("attach fentry/fexit failed", err);

            printf("Attached %s\n", sec);

        } else {
            // Not an attachable section we handle here; skip quietly
            continue;
        }

        if (n_links == cap_links) {
            cap_links *= 2;
            struct bpf_link **tmp = realloc(links, cap_links * sizeof(*links));
            if (!tmp) die("realloc", ENOMEM);
            links = tmp;
        }
        links[n_links++] = link;
    }

    printf("Loaded OK. Arena @ %p (%zu bytes), prot=%s\n",
           mapped, len,
           prot == PROT_NONE ? "NONE" : (prot == PROT_READ ? "RO" : "RW"));
    printf("Press Enter to detach and exit...\n");
    fflush(stdout);
    (void)getchar();

    // 6) Cleanup
    for (size_t i = 0; i < n_links; i++)
        bpf_link__destroy(links[i]);
    free(links);
    munmap(mapped, len);
    bpf_object__close(obj);
    return 0;
}
