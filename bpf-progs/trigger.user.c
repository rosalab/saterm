#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_hello 463


void main() {
   	syscall(__NR_hello);
}
