#!/bin/bash
# Check if the running kernel supports bpf_throw kfunc

echo "Checking for bpf_throw support..."
echo ""

# Method 1: Check kernel symbols
if grep -q "bpf_throw" /proc/kallsyms 2>/dev/null; then
    echo "✓ bpf_throw found in /proc/kallsyms"
    grep "bpf_throw" /proc/kallsyms
else
    echo "✗ bpf_throw not found in /proc/kallsyms"
fi

echo ""

# Method 2: Check kernel version (bpf_throw was added in 6.2+)
kernel_version=$(uname -r | cut -d. -f1-2)
echo "Kernel version: $(uname -r)"

# Method 3: Check BTF for kfunc info
if command -v bpftool &> /dev/null; then
    echo ""
    echo "Checking bpftool btf dump for exception support:"
    if sudo bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -A5 "bpf_throw" | head -10; then
        echo "✓ Found bpf_throw in BTF"
    else
        echo "✗ bpf_throw not found in BTF"
    fi
fi

echo ""
echo "If bpf_throw is not found, you may need to:"
echo "1. Run a kernel with bpf_throw support (6.2+, or your custom branch)"
echo "2. Ensure CONFIG_BPF_JIT and CONFIG_BPF_SYSCALL are enabled"

