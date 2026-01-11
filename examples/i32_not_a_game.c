#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#define GET_PID() GetCurrentProcessId()
#else
#include <unistd.h>
#include <sys/types.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#define GET_PID() getpid()
#endif

int main()
{
    int not_money = 0;
    int *addr = &not_money; // !
    unsigned int pid = (unsigned int)GET_PID();

    while (1)
    {
        not_money += 11;
        // printf("[PID: %u, target: %p] -> Not in-game currency = %d\n", pid, &not_money, not_money); // will shadow lookup since the tmp is too fast
        printf("[PID: %u, target: %p] -> Not in-game currency = %d\n", pid, addr, not_money);
        SLEEP_MS(3000);
    }

    return 0;
}
