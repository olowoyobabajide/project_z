#include "main.h"


int dexfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

static Report *current_report = NULL;

int filecheckDex(char *file_path, Report *r)
{
    current_report = r; // Set static variable for nftw callback
    if (nftw(file_path, dexfile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
    current_report = NULL; // Cleanup
}
int dexfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s", path);
    
        if (fnmatch("*.dex", basename(base_path), 0) == 0)
        {
            if (sb->st_mode & 0740)// check this with the access function instead
            {
               dexScan(base_path, current_report);
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
