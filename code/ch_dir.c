#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>

int extension(const char *a);
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int main(int argc, char **argv)
{
    char buffer[256];
    if (argc < 2)
    {
        printf("Too much input\n");
    }
    sscanf(argv[1], "%255s", &buffer);

    //scan_dir(argv[1]);
    
    if (nftw(argv[1],nfile, 10, FTW_PHYS) == -1)
    {
        perror("nftw");
        return 1;
    }
}

static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{
    /*if (typeflag == FTW_D)
    {
        printf("This is a directory\n");
        printf("Directory: %s\n", path);
        mode_t perms = sb->st_mode & 0777;
        printf("Permission: %03o\n", perms);

    }*/
    if (typeflag == FTW_F && extension(path))
    {
        printf("This is a file\n");
        printf("FILE: %s\n", path);
    }
    return 0;
}
int extension(const char *a)
{
    const char *dot = strchr(a, '.');
    if (!dot || dot == a)
    {
        return 0;
    }

    const char *ext = dot + 1;
    if(strlen(ext) == 3 && tolower(ext[0]) == 'a' && tolower(ext[1]) == 'p' && tolower(ext[2]) == 'k')
    {
        printf("%s\n", a);
    }  
    else
    {
        return(0);
    }
} 