#include <stdio.h>
#include <windows.h>

int main()
{
    int not_money = 0;

    printf("PID: %lu\n", GetCurrentProcessId());
    while (1)
    {
        not_money += 11;
        printf("%p -> Not in-game currency = %d\n", &not_money, not_money);
        Sleep(2000);
    }
}
