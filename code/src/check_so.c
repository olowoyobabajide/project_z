#include "main.h"


int sofile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);
int filecheckso(char *file_path);
int filecheckso(char *file_path)
{
    if (nftw(file_path, sofile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
}
int sofile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s/temp", path);
    
        if (fnmatch("*.so", basename(base_path), 0) == 0)
        {
            if (sb->st_mode & 0740)// check this with the access function instead
            {
               isoFunc(base_path);
               hash_sum(base_path);
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

