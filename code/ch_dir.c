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

void unzip_apk(char *apk);
int apk_check(char *apk);
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int main(int argc, char **argv)
{
    extern static char buffer[PATH_MAX];

    sscanf(argv[1], "%255s", &buffer);
    apk_check(buffer);

}

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
        static char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s", path);
        char apk[PATH_MAX];
        snprintf(apk, PATH_MAX-1, "unzip %s -d temp", path);

        if (fnmatch("*.apk", basename(base_path), 0) == 0)
        {
            
            if (sb->st_mode & 0740)
            {
                printf("File: %s\n", path);
                system(apk);
                
            }
            else
            {
                perror("Permission denied");
                return EXIT_FAILURE;
            }
        }
    }
    return 0; 
}

