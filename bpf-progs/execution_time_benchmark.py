#!/usr/bin/env python3
"""
Benchmark for measuring BPF program EXECUTION TIME using kernel stats

This script measures the actual execution time of BPF programs using
kernel-collected statistics (run_time_ns / run_cnt).

THREE MODES:
1. baseline - No termination at all (pure overhead)
2. bpf_throw - Exception-based termination
3. stub - Helper stubbing via bpftool prog terminate

METHODOLOGY:
  1. Enable BPF stats: sysctl -w kernel.bpf_stats_enabled=1
  2. Load BPF program and start workload
  3. Read baseline stats (run_time_ns, run_cnt)
  4. For bpf_throw/stub: trigger termination
  5. Wait for more invocations
  6. Read final stats
  7. Calculate average execution time: delta_run_time_ns / delta_run_cnt

This measures the ACTUAL BPF program execution time, not subprocess overhead.
"""

import subprocess
import time
import statistics
import os
import signal
import sys
import argparse
import re
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class BPFStats:
    run_time_ns: int
    run_cnt: int
    avg_time_ns: float = 0.0
    
    def __post_init__(self):
        if self.run_cnt > 0:
            self.avg_time_ns = self.run_time_ns / self.run_cnt

class BPFProgramManager:
    """Manages BPF program compilation, loading, and cleanup"""
    
    def __init__(self, script_dir: str, mode: str):
        self.script_dir = script_dir
        self.mode = mode
        
        # Select appropriate kernel program based on mode
        if mode == "baseline":
            kern_base = "termination_latency_test_baseline"
        elif mode == "bpf_throw":
            kern_base = "termination_latency_test_throw"
        else:  # stub
            kern_base = "termination_latency_test_stub"
        
        self.bpf_kern_source = os.path.join(script_dir, f"{kern_base}.kern.c")
        self.bpf_kern_object = os.path.join(script_dir, f"{kern_base}.kern.o")
        self.bpf_user_source = os.path.join(script_dir, "termination_latency_test.user.c")
        self.bpf_user_binary = os.path.join(script_dir, "termination_latency_test.user")
        self.user_process = None
        self.prog_id = None
        self.control_map_id = None
        self.counter_map_id = None
        
    def compile(self) -> bool:
        """Compile everything using Makefile"""
        try:
            print(f"Running make to compile all programs...")
            
            result = subprocess.run([
                "make"
            ], check=True, capture_output=True, cwd=self.script_dir, text=True)
            
            kern_obj = os.path.basename(self.bpf_kern_object)
            print(f"✓ Compiled successfully (including {kern_obj})")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Compilation failed:")
            if e.stderr:
                print(e.stderr)
            if e.stdout:
                print(e.stdout)
            return False
    
    def load_and_attach(self) -> Tuple[bool, Optional[int], Optional[int]]:
        """Load and attach BPF program using user program"""
        try:
            print(f"Loading and attaching BPF program...")
            
            self.user_process = subprocess.Popen(
                [self.bpf_user_binary, self.bpf_kern_object],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            prog_id = None
            control_map_id = None
            counter_map_id = None
            
            for line in self.user_process.stdout:
                line = line.strip()
                if line.startswith("PROG_ID="):
                    prog_id = int(line.split('=')[1])
                    print(f"✓ Loaded program with ID: {prog_id}")
                elif line.startswith("CONTROL_MAP_ID="):
                    control_map_id = int(line.split('=')[1])
                    print(f"✓ Found control_map ID: {control_map_id}")
                elif line.startswith("COUNTER_MAP_ID="):
                    counter_map_id = int(line.split('=')[1])
                    print(f"✓ Found counter_map ID: {counter_map_id}")
                elif line == "READY":
                    print(f"✓ BPF program ready")
                    break
            
            if prog_id is None:
                print("✗ Failed to get program ID from user program")
                return (False, None, None)
            
            self.prog_id = prog_id
            self.control_map_id = control_map_id
            self.counter_map_id = counter_map_id
            
            return (True, prog_id, control_map_id)
            
        except Exception as e:
            print(f"✗ Failed to load/attach: {e}")
            return (False, None, None)
    
    def cleanup(self):
        """Cleanup BPF program resources"""
        try:
            if self.user_process:
                print("Stopping user program...")
                self.user_process.terminate()
                try:
                    self.user_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.user_process.kill()
                    self.user_process.wait()
                print(f"✓ User program stopped")
        except Exception as e:
            print(f"Warning: Cleanup failed: {e}")

class WorkloadManager:
    """Manages the workload that triggers the BPF program"""
    
    def __init__(self, script_dir: str):
        self.script_dir = script_dir
        self.saterm_test = os.path.join(script_dir, "saterm.test")
        self.process = None
        
    def ensure_built(self) -> bool:
        """Ensure saterm.test is built"""
        if not os.path.exists(self.saterm_test):
            print("Building saterm.test...")
            try:
                subprocess.run(["make", "saterm.test"], 
                             check=True, cwd=self.script_dir)
                print("✓ Built saterm.test")
                return True
            except subprocess.CalledProcessError:
                print("✗ Failed to build saterm.test")
                return False
        return True
    
    def start(self, duration: int = 120) -> bool:
        """Start the workload"""
        try:
            print(f"Starting workload (saterm.test for {duration}s)...")
            self.process = subprocess.Popen(
                [self.saterm_test, str(duration), "0.001"],  # Very fast to get many samples
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.5)  # Give it time to start
            print(f"✓ Workload started (PID: {self.process.pid})")
            return True
        except Exception as e:
            print(f"✗ Failed to start workload: {e}")
            return False
    
    def stop(self):
        """Stop the workload"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
                print("✓ Workload stopped")
            except:
                self.process.kill()
                self.process.wait()

class BPFStatsReader:
    """Read BPF program statistics from kernel"""
    
    @staticmethod
    def enable_stats() -> bool:
        """Enable BPF statistics collection"""
        try:
            subprocess.run([
                "sysctl", "-w", "kernel.bpf_stats_enabled=1"
            ], check=True, capture_output=True)
            print("✓ BPF stats enabled")
            return True
        except subprocess.CalledProcessError:
            print("✗ Failed to enable BPF stats (need root?)")
            return False
    
    @staticmethod
    def read_stats(prog_id: int) -> Optional[BPFStats]:
        """Read run_time_ns and run_cnt for a program"""
        try:
            output = subprocess.check_output([
                "bpftool", "prog", "show", "id", str(prog_id)
            ], text=True)
            
            # Parse output for run_time_ns and run_cnt
            # Example: "379: raw_tracepoint [...] run_time_ns 35875602162 run_cnt 160512637"
            run_time_match = re.search(r'run_time_ns (\d+)', output)
            run_cnt_match = re.search(r'run_cnt (\d+)', output)
            
            if run_time_match and run_cnt_match:
                run_time_ns = int(run_time_match.group(1))
                run_cnt = int(run_cnt_match.group(1))
                return BPFStats(run_time_ns, run_cnt)
            else:
                print(f"Warning: Could not parse stats from output:\n{output}")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to read stats: {e}")
            return None

class ExecutionTimeBenchmark:
    """Benchmark BPF program execution time"""
    
    def __init__(self, prog_id: int, mode: str, control_map_id: Optional[int] = None):
        self.prog_id = prog_id
        self.mode = mode
        self.control_map_id = control_map_id
        self.stats_reader = BPFStatsReader()
    
    def trigger_bpf_throw(self) -> bool:
        """Trigger bpf_throw by writing to control map"""
        if not self.control_map_id:
            print("✗ Control map ID not provided for bpf_throw mode")
            return False
        
        try:
            subprocess.run([
                "bpftool", "map", "update",
                "id", str(self.control_map_id),
                "key", "0", "0", "0", "0",
                "value", "1", "0", "0", "0", "0", "0", "0", "0"
            ], check=True, capture_output=True, timeout=5)
            print("✓ Triggered bpf_throw (set control_map[0] = 1)")
            return True
        except Exception as e:
            print(f"✗ Failed to trigger bpf_throw: {e}")
            return False
    
    def trigger_stub_termination(self) -> bool:
        """Trigger stub-based termination"""
        try:
            subprocess.run([
                "bpftool", "prog", "terminate", "id", str(self.prog_id)
            ], check=True, capture_output=True, timeout=5)
            print("✓ Triggered stub-based termination")
            return True
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else ""
            if "unknown" in stderr.lower() or "invalid" in stderr.lower():
                print("✗ bpftool prog terminate not available (wrong branch?)")
            else:
                print(f"✗ Failed to trigger stub termination: {stderr}")
            return False
        except Exception as e:
            print(f"✗ Failed to trigger stub termination: {e}")
            return False
    
    def run_benchmark(self, measurement_duration: int = 10):
        """
        Run execution time benchmark
        
        Steps:
        1. Read initial stats
        2. For bpf_throw/stub modes: trigger termination
        3. Wait for measurement_duration seconds while workload runs
        4. Read final stats
        5. Calculate average execution time
        """
        mode_name = {
            "baseline": "Baseline (no termination)",
            "bpf_throw": "bpf_throw (KFLEX)",
            "stub": "Stub-based termination"
        }.get(self.mode, self.mode)
        
        print()
        print("=" * 70)
        print(f"Running execution time benchmark: {mode_name}")
        print("=" * 70)
        print()
        
        # Step 1: Read initial stats
        print("Reading initial stats...")
        initial_stats = self.stats_reader.read_stats(self.prog_id)
        if not initial_stats:
            print("✗ Failed to read initial stats")
            return
        
        print(f"  Initial run_cnt: {initial_stats.run_cnt}")
        print(f"  Initial run_time_ns: {initial_stats.run_time_ns}")
        print()
        
        # Step 2: For termination modes, trigger termination
        if self.mode == "bpf_throw":
            print("Triggering bpf_throw...")
            if not self.trigger_bpf_throw():
                return
            print()
        elif self.mode == "stub":
            print("Triggering stub termination...")
            if not self.trigger_stub_termination():
                return
            print()
        
        # Step 3: Wait while collecting samples
        print(f"Measuring for {measurement_duration} seconds...")
        print("(Workload is continuously triggering BPF program)")
        
        for i in range(measurement_duration):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{measurement_duration} seconds elapsed...")
        print()
        
        # Step 4: Read final stats
        print("Reading final stats...")
        final_stats = self.stats_reader.read_stats(self.prog_id)
        if not final_stats:
            print("✗ Failed to read final stats")
            return
        
        print(f"  Final run_cnt: {final_stats.run_cnt}")
        print(f"  Final run_time_ns: {final_stats.run_time_ns}")
        print()
        
        # Step 5: Calculate and display results
        self.print_results(initial_stats, final_stats, mode_name)
    
    def print_results(self, initial: BPFStats, final: BPFStats, mode_name: str):
        """Calculate and print benchmark results"""
        
        delta_run_cnt = final.run_cnt - initial.run_cnt
        delta_run_time_ns = final.run_time_ns - initial.run_time_ns
        
        print("=" * 70)
        print(f"{mode_name} - RESULTS")
        print("=" * 70)
        print()
        
        if delta_run_cnt == 0:
            print("❌ No BPF program invocations during measurement!")
            print("   (Is the workload running? Are syscalls being made?)")
            return
        
        avg_time_ns = delta_run_time_ns / delta_run_cnt
        avg_time_us = avg_time_ns / 1000
        
        print(f"Measurement Summary:")
        print(f"  Invocations during measurement: {delta_run_cnt:,}")
        print(f"  Total execution time:            {delta_run_time_ns:,} ns")
        print()
        print(f"Average Execution Time per Invocation:")
        print(f"  {avg_time_ns:,.2f} ns  ({avg_time_us:.2f} μs)")
        print()

def main():
    parser = argparse.ArgumentParser(
        description='Measure BPF program execution time using kernel statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Baseline (no termination):
  sudo ./execution_time_benchmark.py --mode baseline --duration 10
  
  # bpf_throw mode (requires bpf_throw branch):
  sudo ./execution_time_benchmark.py --mode bpf_throw --duration 10
  
  # Stub mode (requires stub branch):
  sudo ./execution_time_benchmark.py --mode stub --duration 10

This script uses kernel-collected BPF statistics (run_time_ns, run_cnt)
to measure ACTUAL execution time of the BPF program.

Branch requirements:
  - baseline: Any branch
  - bpf_throw: Use 'bpf_throw' branch (has bpf_throw kfunc)
  - stub: Use stub-based termination branch (has bpftool prog terminate)
        """
    )
    
    parser.add_argument('--mode', type=str, required=True, 
                        choices=['baseline', 'bpf_throw', 'stub'],
                        help='Test mode')
    parser.add_argument('--duration', type=int, default=10,
                        help='Measurement duration in seconds (default: 10)')
    parser.add_argument('--no-compile', action='store_true',
                        help='Skip compilation (use existing .o file)')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("BPF Program Execution Time Benchmark")
    print("=" * 70)
    print(f"Mode:     {args.mode}")
    print(f"Duration: {args.duration}s")
    print()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (for BPF operations)")
        sys.exit(1)
    
    # Initialize managers
    bpf_manager = BPFProgramManager(script_dir, args.mode)
    workload_manager = WorkloadManager(script_dir)
    stats_reader = BPFStatsReader()
    
    try:
        # Step 1: Enable BPF stats
        if not stats_reader.enable_stats():
            sys.exit(1)
        print()
        
        # Step 2: Compile BPF program
        if not args.no_compile:
            if not bpf_manager.compile():
                print("ERROR: Compilation failed")
                sys.exit(1)
            print()
        
        # Step 3: Load and attach BPF program
        success, prog_id, control_map_id = bpf_manager.load_and_attach()
        if not success:
            print("ERROR: Failed to load/attach BPF program")
            sys.exit(1)
        print()
        
        # Step 4: Build and start workload
        if not workload_manager.ensure_built():
            sys.exit(1)
        
        if not workload_manager.start():
            sys.exit(1)
        print()
        
        # Give workload time to start generating syscalls
        print("Waiting for workload to stabilize...")
        time.sleep(2)
        print()
        
        # Step 5: Run benchmark
        benchmark = ExecutionTimeBenchmark(prog_id, args.mode, control_map_id)
        benchmark.run_benchmark(args.duration)
        
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        print()
        print("=" * 70)
        print("Cleanup")
        print("=" * 70)
        workload_manager.stop()
        bpf_manager.cleanup()

if __name__ == "__main__":
    main()

