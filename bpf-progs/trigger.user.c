#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define __NR_saterm_test 470

int main(void)
{
    errno = 0;
    long ret = syscall(__NR_saterm_test);
    if (ret == -1) {
        perror("syscall saterm_test failed");
    } else {
        printf("saterm_test returned %ld\n", ret);
    }
    return 0;
}
