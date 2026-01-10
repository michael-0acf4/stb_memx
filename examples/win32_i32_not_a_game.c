#include <stdio.h>
#include <windows.h>

int main()
{
    int not_money = 696969;

    printf("PID: %lu\n", GetCurrentProcessId());
    while (1)
    {
        printf("Not in-game currency = %d\n", not_money);
        Sleep(2000);
    }
}
