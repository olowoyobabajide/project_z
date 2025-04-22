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

int extension(const char *a);
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int main(int argc, char **argv)
{
    char buffer[PATH_MAX];

    sscanf(argv[1], "%255s", &buffer);
    if (argc > 2)
    {
        printf("Too much input\n");
        return EXIT_FAILURE;
    }
    
    if (nftw(buffer, nfile, 10, FTW_PHYS) == -1)
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

        if (fnmatch("*.config", basename(base_path), 0) == 0)
        {
            printf("File: %s\n", path);
        }
    }
    return 0; 
}
