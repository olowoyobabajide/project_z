#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <glob.h>
#define PATH_MAX 256

int extension(const char *a);
static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);
int pattern_check(const char *epath, int eerrno);

int main(int argc, char **argv)
{
    char buffer[256];

    if (argc < 2)
    {
        printf("Too much input\n");
    }
    sscanf(argv[1], "%255s", &buffer);
    
    if (nftw(argv[1], nfile, 10, FTW_PHYS) == -1)
    {
        perror("nftw");
        return 1;
    }
    
}

static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{
    if (typeflag != FTW_F)
    {
        return 0;

    }
    glob_t check;
   
    /*char pattern[PATH_MAX];
    snprintf(pattern, PATH_MAX-1, "%s/*.pdf", path);
*/
    int ret = glob("*.pdf", 0, NULL, &check);
    if (ret == 0)
    {
        for (size_t i = 0; i < check.gl_pathc; i++)
        {
            printf("File : %s", check.gl_pathv[i]);
        }
        globfree(&check);
    }
    else if (ret == GLOB_NOMATCH)
    {
        printf("No matching file\n");
    }
    else
    {
        printf("Glob failed\n");   
    }
   
    /*if (typeflag == FTW_F)
    {
    
        printf("This is a file\n");
        printf("FILE: %s\n", path);
    }*/
    
    return 0;
    
}
int pattern_check(const char *epath, int eerrno)
{
    if (epath == NULL)
    {
        printf("You made a mistake\n");
        return(eerrno);
    }
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