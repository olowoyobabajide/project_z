#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    int start_work;
    int start_pomodoro = 1;
    int short_break, long_break, work_seconds;

    while(1)
    {
        while(work_seconds >= 0)
        {
            work_seconds = 1500;
            if(work_seconds == 0){ 
                short_break = 300;
                
                while(short_break > 0)
                {
                    printf("Take a break. Look away from the screen and rest\n");
                    printf("You have %d seconds left\n", short_break);
                    sleep(1);
                    short_break--;
                }
                break;
            }
            else{
                    printf("Seconds remaining for work %d\n", work_seconds);
                    sleep(1);
                    work_seconds--;

            }
        }

        
        if ((start_pomodoro % 4) == 0)
        {
            long_break = 1800;
            system("killall code");
            while(long_break > 0)
            {
               printf("Snooze.....\n");
               printf("You have %d seconds left\n", long_break);
               sleep(1);
               long_break--;
               
            }
        }
        printf("Pomodoro's done: %d\n", start_pomodoro);
        start_pomodoro++;
    }
    
}