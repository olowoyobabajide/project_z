#include "main.h"

void suid(char* file, Report *r){
    char cmd[256];
    char risky_perm[15];
    FILE *perm_pointer;
    snprintf(cmd, 255, "stat --printf=%%A \"%s\"",file);
    if((perm_pointer = popen(cmd, "r"))){
        if(fgets(risky_perm, 15, perm_pointer) != NULL){
            risky_perm[strcspn(risky_perm, "\r\n")] = '\0';

            if(strchr(risky_perm, 's')){
                add_finding(r, FINDING_PERMISSION, "SUID Permission Set", "HIGH", "File has SUID bit set, allowing execution with owner privileges.", risky_perm, file, "SUID bit detected");
            }
            if(strstr(risky_perm, "rwxrwxrwx")){
                add_finding(r, FINDING_PERMISSION, "World Writable File", "HIGH", "File is world-writable, allowing any user to modify it.", risky_perm, file, "rwxrwxrwx detected");
            }
        }
        
    }
    pclose(perm_pointer);
}

void hidden_file(char *file, Report *r){
    if(fnmatch(".*", basename(file), 0) == 0){
        add_finding(r, FINDING_PERMISSION, "Hidden File Detected", "LOW", "Hidden file found in the package, which is unusual and may hide malicious content.", "Hidden", file, basename(file));
    }
}
