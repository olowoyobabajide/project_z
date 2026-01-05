#ifndef REPORT_H
#define REPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    FINDING_PERMISSION,
    FINDING_ACTIVITY,
    FINDING_SERVICE,
    FINDING_RECEIVER,
    FINDING_PROVIDER,
    FINDING_DEX,
    FINDING_ELF,
    FINDING_HASH,
    FINDING_UNKNOWN
} FindingType;

typedef struct Finding {
    FindingType type;
    char *name;
    char *risk_level;
    char *reason;
    char *details; // Extra info like "Exported: true"
    char *source_file; // The file where finding was found (e.g. classes.dex)
    char *evidence; // The specific string/code that triggered the finding
    struct Finding *next;
} Finding;

typedef struct {
    Finding *head;
    Finding *tail;
    int count;
} Report;

Report* init_report();
void add_finding(Report *r, FindingType type, const char *name, const char *risk, const char *reason, const char *details, const char *source_file, const char *evidence);
void save_report_json(Report *r, const char *filename);
void free_report(Report *r);

#endif // REPORT_H
