#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>

#define __NR_hello 470

int main(int argc, char** arg){

	printf("Triggering custom syscall\n");
	syscall(__NR_hello);

	return 0;
}
