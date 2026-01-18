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
{int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{
    zip_t *apk_file;
    apk_file = zip_open(file_path, 0, NULL);
    if(apk_file == NULL){
        return -1;
    }
    int num_entries = zip_get_num_entries(apk_file, 0);
    for(int i = 0; i < num_entries; i++){            
            
            zip_stat_t zstat;
            
            if (fnmatch("*.dex", zip_get_name(apk_file, i, 0), 0) == 0){
                if(zip_stat_index(apk_file, i, 0, &zstat) == -1){
                    return -1;
                }
                zip_file_t *file;
                if((file = zip_fopen_index(apk_file, i, 0)) == NULL){
                    return -1;
                }
                char *buf = malloc(zstat.size);
                if(zip_fread(file, buf, zstat.size) == -1){
                    free(buf);
                    zip_fclose(file);
                    return -1;
                }
                zip_fclose(file);
                dexScan(buf, r);
                free(buf);
            }            
            
    }
    zip_close(apk_file);
    return 0;

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

    char base[PATH_MAX];
    snprintf(base, PATH_MAX-1, "%s", path);
    if (typeflag == FTW_F) {
        if (fnmatch("*.xml", path, 0) == 0 || 
            fnmatch("*.txt", path, 0) == 0){

            remove(path);
        }
    } else if (typeflag == FTW_DP) {        
        if (strcmp(basename(buffer), "temp") == 0) {
            printf("got here");
            rmdir(buffer);
        }
    }

    return 0; 
}
