#ifndef MAIN_H
#define MAIN_H

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>
#include <libgen.h>
#include <sys/wait.h>

#define PATH_MAX 256
int analyse_per(char *a);
int tag_act(char *a);
void tag_perm(char *a);
int apk_check(char *apk);
//static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

#endif