#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define __NR_hello 463
#define DEFAULT_S 60
#define DELAY_S 1

int main(int argc, char* argv[]){
	int secs = argv[1] == NULL ? DEFAULT_S : atoi(argv[1]);

	printf("Starting throughput performance test for test syscall (%ds)...\n", secs);
	printf("-------------------------------------------------------------\n");
	int cnt=0, num_calls=0;

	while(cnt<secs){
		clock_t start_clocks = clock();
		while (clock() - start_clocks < DELAY_S * CLOCKS_PER_SEC) {
			syscall(__NR_hello);
			num_calls++;
		}
		// TODO: this doesn't work if the syscall takes more than a second
		printf("%d:%d\n", cnt, num_calls);
		cnt++;
		num_calls=0;
	}
	
	return 0;
}

