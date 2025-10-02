#define _XOPEN_SOURCE 500
#include <stdio.h>
#include "main.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <fnmatch.h>
#include <libgen.h>

int dexfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int filecheckDex(char *file_path)
{
    if (nftw(file_path, dexfile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
}
int dexfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s", path);
    
        if (fnmatch("*.dex", basename(base_path), 0) == 0)
        {
            if (sb->st_mode & 0740)
            {
               dexScan(base_path);
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

