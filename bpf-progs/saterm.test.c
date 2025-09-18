#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define __NR_hello 470
// #define __NR_hello 79
#define DEFAULT_S 60
#define DELAY_S 1

int main(int argc, char* argv[]){
	double secs = (double) (argv[1] == NULL ? DEFAULT_S : atoi(argv[1]));

	printf("Starting throughput performance test for test syscall (%fs)...\n", secs);
	printf("-------------------------------------------------------------\n");
	double total_time = 0.0;
	int num_calls=0;

	while(total_time < secs){
		clock_t start_clock = clock();
		clock_t now = start_clock;
		while (now - start_clock < DELAY_S * CLOCKS_PER_SEC) {
			syscall(__NR_hello);
			num_calls++;
			now = clock();
		}
		// TODO: this doesn't work if the syscall takes more than a second
		printf("%f:%d\n", total_time, num_calls);
		//cnt++;
		total_time += ((double)(now - start_clock)) / CLOCKS_PER_SEC;

		num_calls=0;
	}

	return 0;
}
