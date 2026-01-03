#include "main.h"
#include <cJSON/cJSON.h>

void vuln_report(const char *level, const char *color, const char *message){
    if(isatty(STDOUT_FILENO)){
        printf("[%s%s%s] %s", color, level, RESET, message);
    }
    else{
        printf("[%s] %s", level, message);
    }
}

void vuln_report_json(const char *name,const char *level, const char *message){
    cJSON *vuln_log_report = cJSON_CreateObject();

    if(vuln_log_report == NULL){
        perror("cJSON_CreateObject");
        return;
    }

    cJSON_AddStringToObject(vuln_log_report, name, level);
    cJSON_AddStringToObject(vuln_log_report, "LEVEL", level);
    cJSON_AddStringToObject(vuln_log_report, "VULNERABILTY", message);

    char *json_str = cJSON_Print(vuln_log_report);

    if(json_str == NULL){
        perror("cJSON_Print");
        cJSON_Delete(vuln_log_report);
        return;
    }

    FILE *log;
    if((log = fopen("findings.json", "a")) != NULL){
        fprintf(log, "%s", json_str);
        fclose(log);
    }
    else{
        perror("findings.json");
        return;
    }

    cJSON_free(json_str);
    cJSON_Delete(vuln_log_report);

}