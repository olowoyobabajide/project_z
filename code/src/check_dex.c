#include "main.h"

static Report *current_report = NULL;

int filecheckDex(char *file_path, int enable_dex_log, Report *r)
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
                dexScan(buf, zstat.size, enable_dex_log, r);
                free(buf);
            }            
            
    }
    zip_close(apk_file);
    return 0;
}