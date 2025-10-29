#include "main.h"

int manifestFile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int filecheckManifest(char *file_path)
{
    if (nftw(file_path, manifestFile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
}
int manifestFile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s/temp", path);
    
        if (strstr(base_path, "AndroidManifest.xml"))
        {
            if (sb->st_mode & 0740)// check this with the access function instead
            {
               analyse_per(path);
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

