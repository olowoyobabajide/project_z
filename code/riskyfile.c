#include "main.h"

void suid(char* file){
    FILE *perm_pointer, *log;

    if((log = fopen("log_suid.txt", "w")) == NULL){
        perror("Unable to create  log for SUID");
    }
    char risky_perm[15];
    char cmd[40];

    snprintf(cmd, 40, "stat --printf=%%A %s",file);

    while(fgets)
    if((perm_pointer = popen(cmd, "r"))){
        if(fgets(risky_perm, 15, perm_pointer) != NULL){
            risky_perm[strcspn(risky_perm, "\r\n")] = '\0';

            if(strchr(risky_perm, 's')){
                fprintf(log, "VULNERABILTY FOUND! SUID permission '%s'\n – anyone who runs the file temporarily gains the owner's privileges\n", risky_perm);   
            }
            if(strstr(risky_perm, "rwxrwxrwx")){
                fprintf(log, "VULNERABILTY FOUND! world writable vulnerability '%s'\n – anyone can modify the file\n", risky_perm); 
            }
        }
        
    }
    pclose(perm_pointer);
    fclose(log);
}
