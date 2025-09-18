#include <unistd.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <sys/socket.h>

int main(void){
    printf("triggering socket syscall\n");

	int sockfd = socket(AF_UNSPEC, SOCK_DGRAM, 0);

	return 0;
}
