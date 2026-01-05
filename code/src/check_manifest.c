#include "main.h"

static Report *current_report = NULL;

int manifestFile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);

int filecheckManifest(char *file_path, Report *r)
{
    current_report = r;
    if (nftw(file_path, manifestFile, 5, FTW_PHYS) == -1)
    {
        perror("nftw");
        current_report = NULL;
        return EXIT_FAILURE;
    }
    current_report = NULL;
    return 0;
}
int manifestFile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{

    if(typeflag == FTW_F)
    {
        char base_path[PATH_MAX];
        snprintf(base_path, PATH_MAX-1, "%s", path);
    
        if(fnmatch("*.xml", basename(base_path), 0) == 0)
        {
            if(strstr(base_path, "AndroidManifest.xml")){
                if (sb->st_mode & 0740)// check this with the access function instead
                {
                    if (current_report) {
                        printf("Analyzing Manifest: %s\n", base_path);
                        analyse_per(base_path, current_report);
                    }
                }
                else
                {
                    perror("Permission Denied");
                    return EXIT_FAILURE;
                }
            }
            
        }
    }
    return 0; 
}
