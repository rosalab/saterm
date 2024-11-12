#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>

#define __NR_hello 463
#define DELAY_S 1

int main(int argc, char** arg){
	printf("Starting throughput performance test for test syscall (10s)...\n");
	printf("-------------------------------------------------------------\n");
	int cnt=0, num_calls=0;

	while(cnt<10){
		clock_t start_clocks = clock();
		while (clock() - start_clocks < DELAY_S * CLOCKS_PER_SEC) {
			syscall(__NR_hello);
			num_calls++;
		}
		printf("%d:%d\n", cnt, num_calls);
		cnt++;
		num_calls=0;
	}
	
	return 0;
}

