# SATerm Development Environment

This repo contains the workflow for testing SAterm (stub-accelerated termination).

## Build Docker Container

```sh
make docker
```

### Update git submodules
The `linux` directory contains a forked linux kernel source tree as a git submodule. The below commands help you to update it.

```sh
git submodule init

# This will take some time.
git submodule update
```

### Build linux

```sh
make vmlinux
make headers-install
make modules-install
```

Also, do
```sh
make libbpf
make bpftool
cd bpf-progs && make && cd ..
```

### Run Qemu
```sh
make qemu-run
```

### If you want to ssh into the qemu
```sh
make qemu-ssh
```

### If you want to enter the docker container where qemu is running
```sh
make enter-docker
```

### If you want to debug the kernel using gdb
```sh
make qemu-run-gdb
```
In an another terminal
```sh
cd linux
gdb vmlinux
target remote:60002
c
```
then set your breakpoints and debug more


### Adding Ports to QEMU
By default host port 52223 is connected to port 52223 inside the QEMU virtual machine.
If you need to be able to connect to more than one port (or a specific port) on your custom kernel from the host, you will have to add new rules.
The needed rules are in `q-script/yifei-q` and in the Makefile.

### Makefile modifications
You must add a line that maps a host port to a Docker port.
In the Makefile you must add a line 
    ```-p 127.0.0.1:HOST_PORT:DOCKER_PORT```
This will map the host port to the docker port.

### q-script modifications
You must modify the q-script to connect the DOCKER_PORT to a QEMU_PORT.
In the q-script you must append a new rule.
Find the line that starts with `"net += -netdev user..."`.
Then at the end of the line add the text ```"hostfwd=tcp::DOCKER_PORT-:QEMU_PORT"```

## Figure reproduction

### Figure 2
In a second window, open a tracelog:

```sh
make qemu-ssh
clear && bpftool prog tracelog
```

Then in the main window:
```sh
cd bpf-progs
./no_helpers_v_helpers.sh
```

### Figure 3/7
```sh
cd bpf-prog
./test_all.sh
```
This will take around 2-3 minutes. The results are in `noterm.txt` and `term.txt`.

### Table 3
For SATerm's throughput:

```sh
make qemu-run
cd bpf-progs
./plain_throughput.user
```

This will print for 1 minute, printing the throughput per second. For our measurements, we calculated the average throughput.

For vanilla Linux's, switch to Linux 6.11 using the following instructions:
```sh
cd linux
git checkout only-test-syscall
cd ..
make vmlinux
```

This branch contains a test system call, but nothing more. Then re-perform the earlier steps to get the "vanilla" numbers.

If you plan to do any other experiments after these, make sure to switch back:
```sh
cd linux
git checkout new-termination
git restore .config
cd ..
make vmlinux
```

The results are logged in the second window.

