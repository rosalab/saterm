# Linux Development Environment

This repo contains the workflow for testing SAterm (stub-accelerated termination).

#### Build Docker Container

``` make docker ```

#### Update git submodules
The `linux` directory contains a forked linux kernel source tree as a git submodule. The below commands help you to update it.

```sh
git submodule init

# This will take some time.
git submodule update
```

#### Copy config file to linux folder

``` cp linux-config/.config ./linux ```

or 

```
cd linux
make defconfig
cd ../
```

#### Build linux

```
make vmlinux
```

#### Run Qemu
```
make qemu-run
```

#### If you want to ssh into the qemu
```
make qemu-ssh
```

#### If you want to enter the docker container where qemu is running
```
make enter-docker
```

#### If you want to debug the kernel using gdb
```
make qemu-run-gdb
```
In an another terminal
```
cd linux
gdb vmlinux
target remote:1234
c
```
then set your breakpoints and debug more


## Adding Ports to QEMU
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

## BPF Enabled
This branch has BPF enabled.
You can use `make libbpf` to build libbpf inside the docker container.
You can use `make bpftool` to build bpftool inside the docker container.
Both have a respective clean target to clean these.

There is also a bpf-progs directory that has a make file to make building bpf programs easy.
There is a naming scheme where programs of the form `*.kern.c` are built as BPF objects, while programs of the form `*.user.c` are
built as user space programs.
