#include "main.h"

int cleanfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf);
int cleanup(char *file_path)
{
    if (nftw(file_path, cleanfile, 5, FTW_DEPTH) == -1)
    {
        perror("nftw");
        return EXIT_FAILURE;
    }
}
int cleanfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{
    if (typeflag == FTW_F) {
        if (fnmatch("*.xml", path, 0) == 0 || 
            fnmatch("*.txt", path, 0) == 0){

            remove(path);
        }
    } else if (typeflag == FTW_DP) {
        if (strcmp("temp", path) == 0) {
            rmdir(path);
        }
    }

    return 0; 
}
