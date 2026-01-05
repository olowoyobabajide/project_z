#include "main.h"

static Report *current_report = NULL;
int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int filecheckAll(char *file_path, Report *r)
{
    current_report = r;
    if (nftw(file_path, nfile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
    current_report = NULL;
}
int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX, "%s", path);
    
        if (fnmatch("*", basename(base_path), 0) == 0)
        {
            if (sb->st_mode & 0740)// check this with the access function instead
            {
                verifyHash(base_path, current_report);
                suid(base_path, current_report);
                hidden_file(base_path, current_report);
                
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
