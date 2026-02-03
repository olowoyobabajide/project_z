/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

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
                add_finding(r, FINDING_PERMISSION, "SUID Permission Set", "HIGH", "File has SUID bit set, allowing execution with owner privileges.", risky_perm, file, "SUID bit detected", NULL, 0);
            }
            if(strstr(risky_perm, "rwxrwxrwx")){
                add_finding(r, FINDING_PERMISSION, "World Writable File", "HIGH", "File is world-writable, allowing any user to modify it.", risky_perm, file, "rwxrwxrwx detected", NULL, 0);
            }
        }
        
    }
    pclose(perm_pointer);
}

void suidMemory(unsigned char *data, size_t size, uint32_t mode, char *filename, Report *r){
    char perm_str[11] = "----------";
    if (mode & S_ISUID) perm_str[0] = 's';
    if (mode & S_ISVTX) perm_str[9] = 't';
    
    if (mode & S_ISUID) {
        add_finding(r, FINDING_PERMISSION, "SUID Permission Set", "HIGH", "File has SUID bit set, which is extremely suspicious in an APK component.", "SUID", filename, "SUID bit detected", NULL, 0);
    }

    if (mode & S_IWOTH){
        add_finding(r, FINDING_PERMISSION, "World Writable File", "HIGH", "File is world-writable, allowing any user to modify it.", "World-Writable", filename, "S_IWOTH bit detected", NULL, 0);
    }
}

void hidden_fileMemory(char *filename, Report *r){
    if(fnmatch(".*", basename(filename), 0) == 0){
        add_finding(r, FINDING_PERMISSION, "Hidden File Detected", "LOW", "Hidden file found in the package, which is unusual and may hide malicious content.", "Hidden", filename, basename(filename), NULL, 0);
    }
}
