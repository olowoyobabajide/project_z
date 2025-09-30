#define _XOPEN_SOURCE 500
#include <stdio.h>
#include "main.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>
#include <libgen.h>
#define PATH_MAX 256

static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);
//int apk_check(char *apk);

int apk_check(char *apk)
{
    if (nftw(apk, nfile, 5, FTW_PHYS) == -1)
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
        char apk[PATH_MAX];
        snprintf(apk, PATH_MAX-1, "apktool d %s -o temp", path);

        if (fnmatch("*.apk", basename(base_path), 0) == 0)
        {
            
            if (sb->st_mode & 0740)
            {
                printf("File: %s\n", path);
                if (system(apk) == -1)
                {
                    perror("Failed to unzip\n");
                }
            }
            else
            {
                perror("Permission Denied");
                return EXIT_FAILURE;
            }
        }
    }
    return 0; 
}

