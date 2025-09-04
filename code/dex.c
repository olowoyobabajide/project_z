#include <stdint.h>
#include "main.h"

/**
 * dex file scanning
 */

void dexPrint(char *str, uint32_t value, FILE *log);
void dexstringData(char *dex);
uint32_t binaryConvert(uint32_t num, uint32_t size);
int main()
{
    dexheaderScan("classes.dex");
    dexstringData("classes.dex");
}
void dexPrint(char *str, uint32_t value, FILE *log){
    /**
     * This function logs the string for the dex file
     * Makes sure the right amount of data is stored
     */
    int size = snprintf(NULL, 0, str, value);

    if (size < 0) {
        fprintf(stderr, "Error during snprintf size calculation.\n");
        return;
    }

    char *buffer = malloc(size + 1);
    if(buffer == NULL){
        fprintf(stderr, "Failed to Allocate Memory\n");
        fclose(log);
    }

    snprintf(buffer, size+1, str, value);
    fprintf(log, "%s", buffer);

    free(buffer);
}

void dexheaderScan(char *dex){

    FILE *file, *dexLog;
    bool safe_dex = true;
    
    if((dexLog = fopen("dexLog.txt", "w")) == NULL){
        fprintf(stderr, "Can't create dex log file\n");
    }
    if((file = fopen(dex, "rb")) == NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
    }

    fprintf(dexLog, "Dex Log\n-----\n");

    while(safe_dex){

        //size_t get_magic;
        unsigned char buf[8];
        
        fread(buf, 1, 8, file);
        if((memcmp(buf, "dex\n035\0", 8)) == 0){
            fprintf(dexLog, "DEX 035 (Android <=5.0) found!\n");
        }
        else if((memcmp(buf, "dex\n036\0", 8)) == 0){
            fprintf(dexLog, "DEX 036 (Android 6.0) found!\n");
        }
        else if((memcmp(buf, "dex\n037\0", 8)) == 0){
            fprintf(dexLog, "DEX 037 (Android 7.0+) found!\n");
        }
        else if((memcmp(buf, "dex\n038\0", 8)) == 0){
            fprintf(dexLog, "DEX 038 (Android 8/9+) found!\n");
        }
        else{
            fprintf(stderr, "Invalid dex file\n");
            safe_dex = false;
        }

        //file size
        uint32_t file_size, header_size, endian_value;
        fseek(file, 0x20, SEEK_SET);
        fread(&file_size, 4, 1, file);

        dexPrint("File size: %u bytes\n", file_size, dexLog);

        //header size
        fseek(file, 0x24, SEEK_SET);
        fread(&header_size, 4, 1, file);
        if (header_size != 112){
            fprintf(stderr, "Invalid header_size");
        }
        dexPrint("Header size: %u bytes (ok)\n", header_size, dexLog);
        
        //endian value
        uint32_t little = 0x12345678;
        uint32_t big = 0x78563412;
        fseek(file, 0x28, SEEK_SET);
        fread(&endian_value, 4, 1, file);
        if((memcmp(&endian_value, &little, 4)) == 0){
            dexPrint("Endian: little (%#04x)\n", endian_value, dexLog);
        }
        else if((memcmp(&endian_value, &big, 4)) == 0){
            dexPrint("Endian: big (%#04x)\n", endian_value, dexLog);
        }
        else{
            fprintf(stderr, "Invalid DEX\n");
            safe_dex = false;
        }

        //string size
        uint32_t string_size, string_id_off;
        fseek(file, 0x38, SEEK_SET);
        fread(&string_size, 4, 1, file);

        dexPrint("String IDs size: %u bytes\n", string_size, dexLog);

        //string  offset
        fseek(file, 0x3C, SEEK_SET);
        fread(&string_id_off, 4, 1, file);

        dexPrint("String IDs offset: %#08x\n", string_id_off, dexLog);
        
        //bounds validation
        if((string_id_off + string_size * 4) > file_size)
        {
            printf("Bad File/Corrupted\n");
            safe_dex = false;           
        }

        //Data size and offset
        uint32_t data_size, data_off;
        fseek(file, 0x68, SEEK_SET);
        fread(&data_size, 4, 1, file);
        fseek(file, 0x6C, SEEK_SET);
        fread(&data_off, 4, 1, file);

        dexPrint("Data Size: %u bytes\n", data_size, dexLog);
        dexPrint("Data Off: %#04x\n", data_off, dexLog);

        break;

    }
    fprintf(dexLog, "\n------\n\n");
    fclose(file);
    fclose(dexLog);
 }

void dexstringData(char *dex){

    
    FILE *file, *dexLog;

    if((dexLog = fopen("dexLog.txt", "a+")) == NULL){
        fprintf(stderr, "Can't create dex log file\n");
    }
    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
    }
    
    uint32_t string_size, string_id_off;
    fseek(file, 0x38, SEEK_SET);
    fread(&string_size, 4, 1, file);
    
    //string  offset
    fseek(file, 0x3C, SEEK_SET);

    int current_string_offset[string_size];

    for(uint32_t i = 0; i < string_size; i++)
    {
        fread(&string_id_off, 4, 1, file);
        dexPrint("string: %d\n", string_id_off, dexLog);
        //current_string_offset[i] = string_id_off;
        //snprintf(stroffset[i], sizeof(uint32_t*), "%d", &string_id_off);
    
    }
    printf("%d\n", binaryConvert(current_string_offset[string_size], 8)); 
    //printf("%d", current_string_offset[string_size]); 
    fclose(dexLog);
}

uint32_t binaryConvert(uint32_t num, uint32_t size){
    uint32_t binary[size];
    uint32_t i = 0;
    
    while(i < size){
        binary[i] = num & 1;
        num = num >> 1;
        i++;
    }

    for(int j = size-1;j > 0;){
        printf("%d", binary[j--]);
    }

}