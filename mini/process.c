#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int main(){
    if(fork() == 0){
        printf("child process: %d\n", getpid());
        printf("child process: %d\n", getpid());
        printf("child process: %d\n", getpid());
        printf("child process: %d\n", getpid());
        printf("child process: %d\n", getpid());
        
        //execve("pomodoro", NULL, NULL);
        exit(0);
    }
    else{
        printf("Parent process: %d\n", getppid());
        printf("Parent process: %d\n", getppid());
        printf("Parent process: %d\n", getppid());
        printf("Parent process: %d\n", getppid());
        printf("Parent process: %d\n", getppid());
        for(int i = 0; i < 4; i++){
            printf("Parent process: %d\n", getppid());
        }
        time_t current;
        time(&current);
        printf("%s", ctime(&current));
        wait(0);
    }
    printf("starting new process\n");
}