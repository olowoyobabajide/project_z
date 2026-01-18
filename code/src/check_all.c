#include "main.h"

int filecheckAll(char *file_path, Report *r)
{
    zip_t *apk_file;
    apk_file = zip_open(file_path, 0, NULL);
    if(apk_file == NULL){
        return -1;
    }
    int num_entries = zip_get_num_entries(apk_file, 0);
    for(int i = 0; i < num_entries; i++){            
            zip_stat_t zstat;
            const char *name = zip_get_name(apk_file, i, 0);
            if (name != NULL){
                if(zip_stat_index(apk_file, i, 0, &zstat) == -1){
                    continue;
                }
                
                zip_uint8_t opsys;
                zip_uint32_t attributes;
                zip_file_get_external_attributes(apk_file, (zip_uint64_t)i, 0, &opsys, &attributes);
                uint32_t mode = (attributes >> 16);

                zip_file_t *file;
                if((file = zip_fopen_index(apk_file, (zip_uint64_t)i, 0)) == NULL){
                    continue;
                }
                unsigned char *buf = malloc(zstat.size);
                if(zip_fread(file, buf, zstat.size) == -1){
                    free(buf);
                    zip_fclose(file);
                    continue;
                }
                zip_fclose(file);
                
                verifyHashMemory(buf, zstat.size, (char*)name, r);
                suidMemory(buf, zstat.size, mode, (char*)name, r);
                hidden_fileMemory((char*)name, r);
                
                free(buf);
            }            
    }
    zip_close(apk_file);
    return 0;
}