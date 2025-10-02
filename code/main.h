#ifndef MAIN_H
#define MAIN_H

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>
#include <libgen.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <libxml/parser.h> 
#include <libxml/tree.h>
#include <time.h>

//#define PATH_MAX 256
int analyse_per(char *a);
void tag_perm(char *a);
int apk_check(char *apk);


// check dex
//int dexfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);
int filecheckDex(char *file_path);


int dexScan(char *);
void analyseDex(
    char **str, int str_count,
    char **typ, int typ_count,
    char **class, int class_count,
    char **method, int method_count,
    char **meth_class, int meth_class_count,
    char **super_class, int super_class_count
);
typedef struct keepinmemory {
    char **strings;
    uint32_t strings_count;
    char **type_descriptors;
    uint32_t type_descriptors_count;
    char **class_definitions;
    uint32_t class_definitions_count;
    char **method_definitions;
    uint32_t method_definitions_count;
    char **method_class;
    uint32_t method_class_count;
    char **super_idx;
    uint32_t super_idx_count;
} keepMemory;
void unsafeFunc(char *dex);
#endif