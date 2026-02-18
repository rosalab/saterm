/*
 * User-space program to measure runtime of eBPF programs at different iteration counts
 * Tests three programs: nested_long, single_linear, and terminated
 * Outputs CSV format: program_name,iteration_count,run_number,runtime_ns
 */

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_saterm_test 470

/* Program configurations */
struct program_config {
  const char *object_file;
  const char *program_name;
  const char *display_name;
};

static const struct program_config programs[] = {
    {"runtime_nested_long.kern.o", "tracepoint_exit_runtime_nested_long",
     "nested_long"},
    {"runtime_single_linear.kern.o", "tracepoint_exit_runtime_single_linear",
     "single_linear"},
    {"runtime_terminated.kern.o", "tracepoint_exit_runtime_terminated",
     "terminated"},
};

#define NUM_PROGRAMS (sizeof(programs) / sizeof(programs[0]))

static volatile bool keep_running = true;
static FILE *csv_file = NULL;
static bool debug_enabled = false;

/* Debug print macro */
#define DEBUG_PRINT(...) \
  do { \
    if (debug_enabled) { \
      fprintf(stderr, "[DEBUG] " __VA_ARGS__); \
    } \
  } while (0)

void signal_handler(int signo) { keep_running = false; }

/* Get BPF program runtime statistics */
static uint64_t get_program_runtime(int prog_fd) {
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);

  if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0) {
    perror("bpf_obj_get_info_by_fd");
    return 0;
  }

  /* run_time_ns is available in recent kernels */
  return info.run_time_ns;
}

/* Dump JIT instructions using bpftool */
/* If output_file is NULL, prints to stderr. Otherwise saves to file. */
static int dump_jit_instructions(__u32 prog_id, const char *label, const char *output_file) {
  if (!debug_enabled) {
    return 0;
  }

  DEBUG_PRINT("JIT Instructions %s (disassembled via bpftool):\n", label);
  DEBUG_PRINT("----------------------------------------\n");
  
  /* Use bpftool at the specified path: /home/rosa/saterm/linux/tools/bpf/bpftool/bpftool */
  char bpftool_path[512] = {0};
  const char *env_path = getenv("BPFTOOL_PATH");
  if (env_path) {
    strncpy(bpftool_path, env_path, sizeof(bpftool_path) - 1);
  } else {
    /* Use absolute path to avoid issues with sudo changing HOME */
    strncpy(bpftool_path, "/home/rosa/saterm/linux/tools/bpf/bpftool/bpftool", sizeof(bpftool_path) - 1);
  }
  
  DEBUG_PRINT("Using bpftool at: %s\n", bpftool_path);
  
  char cmd[1024];
  int ret = snprintf(cmd, sizeof(cmd), 
                    "sudo %s prog dump jited id %u opcodes",
                    bpftool_path, prog_id);
    
  if (ret > 0 && ret < (int)sizeof(cmd)) {
    FILE *fp = popen(cmd, "r");
    if (fp) {
      FILE *out_fp = NULL;
      if (output_file) {
        out_fp = fopen(output_file, "w");
        if (!out_fp) {
          DEBUG_PRINT("Failed to open output file %s: %s\n", output_file, strerror(errno));
          pclose(fp);
          return -1;
        }
      }
      
      char line[1024];
      while (fgets(line, sizeof(line), fp) != NULL) {
        if (out_fp) {
          fputs(line, out_fp);
        } else {
          DEBUG_PRINT("%s", line);
        }
      }
      
      if (out_fp) {
        fclose(out_fp);
        DEBUG_PRINT("Saved JIT dump to: %s\n", output_file);
      }
      
      int status = pclose(fp);
      if (status != 0) {
        DEBUG_PRINT("bpftool exited with status %d\n", status);
      }
    } else {
      DEBUG_PRINT("Failed to execute bpftool: %s\n", strerror(errno));
      DEBUG_PRINT("Command was: %s\n", cmd);
      return -1;
    }
  } else {
    DEBUG_PRINT("Failed to construct bpftool command (buffer too small)\n");
    return -1;
  }
  
  DEBUG_PRINT("----------------------------------------\n");
  return 0;
}

/* Trigger the tracepoint by calling the saterm_test syscall */
static void trigger_tracepoint(void) {
  syscall(__NR_saterm_test);
}

/* Test a single program at a specific iteration count */
static int test_program(const struct program_config *config, int iteration_count,
                        int num_runs) {
  int result = 0;

  DEBUG_PRINT("Testing program: %s (display: %s) at iteration count: %d\n",
          config->program_name, config->display_name, iteration_count);

  /* Run multiple times and measure - each run loads, attaches, triggers, and cleans up */
  DEBUG_PRINT("Starting %d measurement runs...\n", num_runs);
  for (int i = 0; i < num_runs && keep_running; i++) {
    struct bpf_link *link = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = NULL;
    int control_map_fd = -1;
    int prog_fd = -1;
    uint64_t runtime_delta = 0;

    DEBUG_PRINT("Run %d/%d: Loading and attaching program...\n", i + 1, num_runs);

    /* Open BPF object file */
    obj = bpf_object__open_file(config->object_file, NULL);
    if (libbpf_get_error(obj)) {
      fprintf(stderr, "ERROR: opening BPF object file %s failed: %s\n",
              config->object_file, strerror(libbpf_get_error(obj)));
      result = 1;
      goto run_cleanup;
    }

    /* Load the BPF program into the kernel */
    if (bpf_object__load(obj)) {
      fprintf(stderr, "ERROR: loading BPF object file %s failed\n",
              config->object_file);
      result = 1;
      goto run_cleanup;
    }

    /* Find the program by name */
    prog = bpf_object__find_program_by_name(obj, config->program_name);
    if (!prog) {
      fprintf(stderr, "ERROR: could not find program %s in object file %s\n",
              config->program_name, config->object_file);
      result = 1;
      goto run_cleanup;
    }

    /* Get program FD */
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
      fprintf(stderr, "ERROR: getting program fd failed\n");
      result = 1;
      goto run_cleanup;
    }

    /* Get program info for debug (only on first run) */
    char jit_initial_file[256] = {0};
    char jit_after_file[256] = {0};
    __u32 prog_id_for_jit = 0;
    
    if (i == 0 && debug_enabled) {
      struct bpf_prog_info info = {};
      __u32 info_len = sizeof(info);
      
      if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
        prog_id_for_jit = info.id;
        DEBUG_PRINT("Program info - ID: %u, Type: %u, JIT: %s\n",
                info.id, info.type, info.jited_prog_len > 0 ? "yes" : "no");
        if (info.jited_prog_len > 0) {
          DEBUG_PRINT("JIT program length: %u bytes\n", info.jited_prog_len);
          snprintf(jit_initial_file, sizeof(jit_initial_file), 
                   "/tmp/jit_dump_initial_%u_%d", info.id, iteration_count);
          dump_jit_instructions(info.id, "(initial, before first trigger)", jit_initial_file);
        }
      }
    }

    /* Find control map */
    control_map_fd = bpf_object__find_map_fd_by_name(obj, "control_map");
    if (control_map_fd < 0) {
      fprintf(stderr, "ERROR: finding control_map failed\n");
      result = 1;
      goto run_cleanup;
    }

    /* Set iteration count in control map */
    __u32 key = 0;
    if (bpf_map_update_elem(control_map_fd, &key, &iteration_count, BPF_ANY) != 0) {
      perror("ERROR: setting iteration count");
      result = 1;
      goto run_cleanup;
    }

    /* Attach the program to the tracepoint */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
      fprintf(stderr, "ERROR: bpf_program__attach failed: %ld\n",
              libbpf_get_error(link));
      link = NULL;
      result = 1;
      goto run_cleanup;
    }

    /* Get runtime at start of this run */
    uint64_t runtime_before = get_program_runtime(prog_fd);

    /* Trigger the tracepoint */
    trigger_tracepoint();

    /* Get runtime after */
    uint64_t runtime_after = get_program_runtime(prog_fd);

    /* Calculate runtime for this execution */
    runtime_delta = runtime_after - runtime_before;

    /* Dump JIT after first trigger and run diff (only on first run) */
    if (i == 0 && debug_enabled) {
      struct bpf_prog_info info_after = {};
      __u32 info_len_after = sizeof(info_after);
      
      if (bpf_obj_get_info_by_fd(prog_fd, &info_after, &info_len_after) == 0) {
        if (info_after.jited_prog_len > 0 && prog_id_for_jit != 0) {
          snprintf(jit_after_file, sizeof(jit_after_file), 
                   "/tmp/jit_dump_after_%u_%d", info_after.id, iteration_count);
          dump_jit_instructions(info_after.id, "(after first trigger)", jit_after_file);
          
          /* Run diff if we have both files */
          if (jit_initial_file[0] != '\0' && jit_after_file[0] != '\0') {
            DEBUG_PRINT("\n");
            DEBUG_PRINT("=== DIFF: After first trigger vs Initial ===\n");
            char diff_cmd[1024];
            int ret = snprintf(diff_cmd, sizeof(diff_cmd), 
                             "diff -u %s %s", jit_initial_file, jit_after_file);
            if (ret > 0 && ret < (int)sizeof(diff_cmd)) {
              FILE *diff_fp = popen(diff_cmd, "r");
              if (diff_fp) {
                char line[1024];
                int has_diff = 0;
                while (fgets(line, sizeof(line), diff_fp) != NULL) {
                  DEBUG_PRINT("%s", line);
                  has_diff = 1;
                }
                int status = pclose(diff_fp);
                if (!has_diff) {
                  DEBUG_PRINT("(No differences found)\n");
                } else if (WIFEXITED(status)) {
                  int exit_status = WEXITSTATUS(status);
                  /* Exit status 0 = no differences, 1 = differences found (normal), 2 = error */
                  if (exit_status == 2) {
                    DEBUG_PRINT("diff exited with error status %d\n", exit_status);
                  }
                  /* Status 0 or 1 are both normal outcomes */
                } else {
                  DEBUG_PRINT("diff did not exit normally\n");
                }
              } else {
                DEBUG_PRINT("Failed to execute diff: %s\n", strerror(errno));
              }
            }
            DEBUG_PRINT("=== END DIFF ===\n");
            DEBUG_PRINT("\n");
            
            /* Clean up temporary files */
            unlink(jit_initial_file);
            unlink(jit_after_file);
          }
        }
      }
    }

    /* Detach and clean up for this run */
run_cleanup:
    if (link) {
      bpf_link__destroy(link);
      link = NULL;
    }
    if (obj) {
      bpf_object__close(obj);
      obj = NULL;
    }

    /* Output CSV format: program_name,iteration_count,run_number,runtime_ns */
    if (csv_file && result == 0) {
      fprintf(csv_file, "%s,%d,%d,%lu\n", config->display_name, iteration_count, i,
              runtime_delta);
      fflush(csv_file);
    }

    if (result != 0) {
      fprintf(stderr, "ERROR: Failed during run %d/%d\n", i + 1, num_runs);
      break;
    }

    if ((i + 1) % 10 == 0 && debug_enabled) {
      DEBUG_PRINT("Completed %d/%d runs\n", i + 1, num_runs);
    }
  }
  DEBUG_PRINT("Completed all %d measurement runs\n", num_runs);

  return result;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  if (debug_enabled) {
    return vfprintf(stderr, format, args);
  }
  return 0;
}

static void print_usage(const char *prog_name) {
  fprintf(stderr, "Usage: %s <max_iteration> <step_count> <num_runs> [output_csv_file] [--debug]\n",
          prog_name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Arguments:\n");
  fprintf(stderr, "  max_iteration  Maximum iteration count to test\n");
  fprintf(stderr, "  step_count     Linear step size for iteration counts (additive)\n");
  fprintf(stderr, "  num_runs       Number of runs per program/iteration combination\n");
  fprintf(stderr, "  output_csv_file Optional CSV output file (default: results.csv)\n");
  fprintf(stderr, "  --debug        Enable debug output (including JIT disassembly)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Example: %s 64 2 50 results.csv --debug\n", prog_name);
  fprintf(stderr, "  Tests iteration counts: 1, 3, 5, 7, 9, ..., 63\n");
  fprintf(stderr, "  With 50 runs per combination\n");
  fprintf(stderr, "  Output written to results.csv\n");
  fprintf(stderr, "  Debug output enabled\n");
}

int main(int argc, char **argv) {
  if (argc < 4) {
    print_usage(argv[0]);
    return 1;
  }

  /* Parse arguments */
  int max_iteration = atoi(argv[1]);
  int step_count = atoi(argv[2]);
  int num_runs = atoi(argv[3]);
  const char *csv_filename = "results.csv";
  
  /* Parse optional arguments */
  for (int i = 4; i < argc; i++) {
    if (strcmp(argv[i], "--debug") == 0) {
      debug_enabled = true;
    } else if (csv_filename == "results.csv" && argv[i][0] != '-') {
      /* First non-flag argument after required args is CSV filename */
      csv_filename = argv[i];
    }
  }

  if (max_iteration <= 0) {
    fprintf(stderr, "ERROR: max_iteration must be positive\n");
    return 1;
  }

  if (step_count <= 0) {
    fprintf(stderr, "ERROR: step_count must be positive\n");
    return 1;
  }

  if (num_runs <= 0) {
    fprintf(stderr, "ERROR: num_runs must be positive\n");
    return 1;
  }

  /* Open CSV file for writing */
  DEBUG_PRINT("Opening CSV output file: %s\n", csv_filename);
  csv_file = fopen(csv_filename, "w");
  if (!csv_file) {
    perror("ERROR: Failed to open CSV file");
    return 1;
  }
  DEBUG_PRINT("Successfully opened CSV file\n");

  /* Setup signal handler for clean exit */
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Enable libbpf verbose logging only if debug is enabled */
  if (debug_enabled) {
    libbpf_set_print(libbpf_print_fn);
  }

  /* Print CSV header */
  fprintf(csv_file, "program_name,iteration_count,run_number,runtime_ns\n");
  fflush(csv_file);
  DEBUG_PRINT("Wrote CSV header\n");

  /* Test each program */
  DEBUG_PRINT("Starting tests for %zu programs\n", NUM_PROGRAMS);
  for (size_t prog_idx = 0; prog_idx < NUM_PROGRAMS && keep_running;
       prog_idx++) {
    const struct program_config *config = &programs[prog_idx];
    DEBUG_PRINT("========================================\n");
    DEBUG_PRINT("Testing program %zu/%zu: %s\n",
            prog_idx + 1, NUM_PROGRAMS, config->display_name);
    DEBUG_PRINT("========================================\n");

    /* Generate and test each iteration count */
    for (int iteration_count = 1; iteration_count <= max_iteration && keep_running;
         iteration_count += step_count) {
      DEBUG_PRINT("--- Testing iteration count: %d ---\n", iteration_count);
      if (test_program(config, iteration_count, num_runs) != 0) {
        fprintf(stderr, "ERROR: Failed to test %s at iteration count %d\n",
                config->display_name, iteration_count);
        fclose(csv_file);
        return 1;
      }
      DEBUG_PRINT("--- Completed iteration count: %d ---\n", iteration_count);

      /* Small delay between different iteration counts */
      // usleep(50000);
    }
    DEBUG_PRINT("Completed all tests for program: %s\n", config->display_name);
  }

  DEBUG_PRINT("All tests completed. Closing CSV file...\n");
  fclose(csv_file);
  DEBUG_PRINT("Results written to: %s\n", csv_filename);
  return 0;
}
