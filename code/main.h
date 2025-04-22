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
#define PATH_MAX 256

extern char base_path[PATH_MAX];

void unzip_apk(char *apk);
int apk_check(char *apk);
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int apk_check(char *apk)
{
    if (nftw(apk, nfile, 10, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
}
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s", path);

        if (fnmatch("*.apk", basename(base_path), 0) == 0)
        {
            printf("File: %s\n", path);
        }
    }
    return 0; 
}

void unzip_apk(char *apk)
{
    while(apk != NULL)
    {
        system("unzip");
    }
}


#endif