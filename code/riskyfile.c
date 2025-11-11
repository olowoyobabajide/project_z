#include "main.h"

void suid(char* file){
    FILE *perm_pointer, *log;

    if((log = fopen("log_suid.txt", "w")) == NULL){
        perror("Unable to create  log for SUID");
    }
    char risky_perm[15];
    char cmd[256];

    snprintf(cmd, 255, "stat --printf=%%A \"%s\"",file);

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

void hidden_file(char *file){
    if(fnmatch(".*", basename(file), 0)){
        printf("FOUND A HIDDEN file\n");
        printf("%s\n", file);
        printf("LOW SEVERITY! It's not a guaranteed vulnerability, but it is unusual and warrants a manual review\n");
    }
}
