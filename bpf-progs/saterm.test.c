#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define __NR_hello 470
#define DEFAULT_TOTAL_SECS 60.0
#define DEFAULT_INTERVAL_SECS 0.5

static inline double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char* argv[]) {
    double total_secs   = (argc > 1) ? strtod(argv[1], NULL) : DEFAULT_TOTAL_SECS;
    double interval_sec = (argc > 2) ? strtod(argv[2], NULL) : DEFAULT_INTERVAL_SECS;
    if (interval_sec <= 0.0) interval_sec = DEFAULT_INTERVAL_SECS;

    // Line-buffer stdout so each line appears promptly.
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("Starting throughput performance test for test syscall (%.3fs total, %.3fs interval)...\n",
           total_secs, interval_sec);
    printf("----------------------------------------------------------------------------------\n");

    double t_start = now_sec();
    double next_mark = t_start + interval_sec;
    int num_calls_interval = 0;

    for (;;) {
        // Run the syscall as fast as possible.
        syscall(__NR_hello);
        num_calls_interval++;

        double t_now = now_sec();
        double elapsed = t_now - t_start;

        // Print once per interval with floating-point timestamp.
        if (t_now >= next_mark) {
            printf("%.3f:%d\n", elapsed, num_calls_interval);
            num_calls_interval = 0;
            // Move to the next interval; handle drift by stepping forward repeatedly if needed.
            do { next_mark += interval_sec; } while (t_now >= next_mark);
        }

        // Stop once total time is reached.
        if (elapsed >= total_secs) break;
    }

    // If there were leftover calls in a partial interval, report them too.
    // Use the exact final elapsed time.
    if (num_calls_interval > 0) {
        double elapsed = now_sec() - t_start;
        printf("%.3f:%d\n", elapsed, num_calls_interval);
    }

    return 0;
}

