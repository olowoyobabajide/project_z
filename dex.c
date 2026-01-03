#include "main.h"


/**
 * Dex File Scanning
 * 
*/
typedef struct resolvedMethod{
    uint32_t methodIdx;
    uint32_t accessFlags;
    uint32_t code_off;
}*method;
typedef struct keepinmemory {
    char **strings;
    uint32_t strings_count;
    char **type_descriptors;
    uint32_t type_descriptors_count;
    char **class_definitions;
    uint32_t class_definitions_count;
    char **method_definitions;
    uint32_t method_definitions_count;
    char **method_class;
    uint32_t method_class_count;
    char **super_idx;
    uint32_t super_idx_count;
    uint16_t *code_byte;
    uint32_t code_byte_count;
} keepMemory;
keepMemory dataInMemory;
void dexPrint(char *str, uint32_t value, FILE *log);
void dexheaderScan(char *dex, FILE*);
void dexstringData(char *dex, FILE*);
char* readDexString(FILE *file);
uint32_t readULEB128(FILE *file);
void typeIdTable(char *dex, FILE*);
void methodIdTable(char *, FILE*, uint32_t *, char **);
void fieldIdTable(char *, FILE*,uint32_t *, char **);
void classDefTable(char *, FILE*,uint32_t *, char **);
void class_data_item(char *, FILE*,uint32_t *, uint32_t );
void code_item(char *dex, FILE *dexLog, method , method, uint32_t size);
int logdex(char *);

void freeKeepMemory(keepMemory mem);

int dexScan(char *dex, Report *report)
{

    logdex(dex);
    printf("main: before analyseDex\n"); fflush(stdout);
    analyseDex(
        dataInMemory.strings, dataInMemory.strings_count,
        dataInMemory.type_descriptors, dataInMemory.type_descriptors_count,
        dataInMemory.class_definitions, dataInMemory.class_definitions_count,
        dataInMemory.method_definitions, dataInMemory.method_definitions_count,
        dataInMemory.method_class, dataInMemory.method_class_count,
        dataInMemory.super_idx, dataInMemory.super_idx_count,
        report,
        dex
    );
    printf("main: after analyseDex\n"); fflush(stdout);
    freeKeepMemory(dataInMemory);
    
    return 0;
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

    snprintf(buffer, size + 1, str, value);
    fprintf(log, "%s", buffer);

    free(buffer);
}

void dexheaderScan(char *dex, FILE *dexLog){
    printf("dexheaderScan: called\n"); fflush(stdout);

    FILE *file;
    bool safe_dex = true;
    
    if((file = fopen(dex, "rb")) == NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
    }

    fprintf(dexLog, "[Dex_Log]\n-----\n");

    while(safe_dex){

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

        dexPrint("String IDs offset: %#04x\n", string_id_off, dexLog);
        
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
    fprintf(dexLog, "------\n\n");
    fclose(file);
 }

void dexstringData(char *dex, FILE *dexLog){
    printf("dexstringData: called\n"); fflush(stdout);

    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
    }

    uint32_t string_size, string_id_off;
    fseek(file, 0x38, SEEK_SET);
    fread(&string_size, 4, 1, file);
    
    //string  offset
    fseek(file, 0x3C, SEEK_SET);
    
    int *current_string_offset = malloc(string_size * sizeof(int));
    if (!current_string_offset) {
        fprintf(stderr, "Failed to allocate memory for string offsets\n");
        fclose(file);
        return;
    }
    for(uint32_t i = 0; i < string_size; i++)
    {
        fread(&string_id_off, 4, 1, file);
        current_string_offset[i] = string_id_off;
    }
    dataInMemory.strings = malloc(string_size * sizeof(char*));
    dataInMemory.strings_count = string_size;
    if (!dataInMemory.strings) {
        fprintf(stderr, "Failed to allocate memory for strings array\n");
        free(current_string_offset);
        fclose(file);
        return;
    }
    for(uint32_t j = 0; j < string_size; j++){
        fseek(file, current_string_offset[j], SEEK_SET);
        char *str = readDexString(file);
        if(str){
            dataInMemory.strings[j] = str;
            fprintf(dexLog, "%s\n", dataInMemory.strings[j]);
        }
    }
    free(current_string_offset);

    cleanup:
        fclose(file);
}
char* readDexString(FILE *file){
    size_t count = 0;
    int c;
    uint32_t length = readULEB128(file);
    size_t bufSize = (length*4)+1;
    char* buffer = malloc(bufSize);

    if(!buffer)return NULL;

    while(count < length && count < bufSize-1){
        fread(&c, 1, 1, file);
        buffer[count++] = (char)c;
    }

    buffer[count] = '\0';
    return buffer;
}
uint32_t readULEB128(FILE *file){
    uint32_t result = 0;
    int shift = 0;
    uint8_t byte;

    while(1){
        fread(&byte, 1, 1, file);
        result |= (byte & 0x7F) << shift;

        if((byte & 0x80) == 0)break;
        shift +=7;
    }
    return result;
}

void typeIdTable(char *dex, FILE *dexLog){
    printf("typeIdTable: called\n"); fflush(stdout);

    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
    }

    uint32_t string_size, string_id_off;
    fseek(file, 0x38, SEEK_SET);
    fread(&string_size, 4, 1, file);
    
    //string  offset
    fseek(file, 0x3C, SEEK_SET);
    
    uint32_t *current_string_offset = malloc(sizeof(uint32_t) * string_size);
    if (current_string_offset == NULL) {
        perror("Error allocating memory for string offsets\n");
        goto cleanup;
    }
    for(uint32_t i = 0; i < string_size; i++)
    {
        fread(&string_id_off, 4, 1, file);
        current_string_offset[i] = string_id_off;
    }
    char **string_data_array = NULL;
    char *str;
    string_data_array = malloc(string_size * sizeof(char*));
    if (string_data_array == NULL){
        perror("Error allocating memory for string size\n");
        goto cleanup;
    }
    for(uint32_t j = 0; j < string_size; j++){
        fseek(file, current_string_offset[j], SEEK_SET);
        str = readDexString(file);
        if(str){
            string_data_array[j] = str;
        } 
    }
    free(current_string_offset); // Free the offset array now that I am done with it
    
    uint32_t type_ids_size, type_ids_off;
    //type ids size
    fseek(file, 0x40, SEEK_SET);
    fread(&type_ids_size, 4, 1, file);

    fseek(file, 0x44, SEEK_SET);
    fread(&type_ids_off, 4, 1, file);

    fseek(file, type_ids_off, SEEK_SET);
    uint32_t *string_index = NULL;

    string_index = malloc(sizeof(uint32_t) * type_ids_size);
    if(string_index == NULL){
        perror("Error allocating memory for type ids size\n");
        goto cleanup;
    }
    
    dataInMemory.type_descriptors = malloc(type_ids_size * sizeof(char*));
    dataInMemory.type_descriptors_count = type_ids_size;
    for(uint32_t i = 0; i < type_ids_size; i++){
        uint32_t offset;
        fread(&offset, 4, 1, file);
        string_index[i] = offset;
        dataInMemory.type_descriptors[i] = string_data_array[string_index[i]];
        fprintf(dexLog, "[TYPE] index=%d, decriptor=%s\n", string_index[i], dataInMemory.type_descriptors[i]);
    }
    printf("MethodIdTable: calling methodIdTable\n"); fflush(stdout);
    methodIdTable(dex, dexLog, string_index, dataInMemory.strings);
    printf("MethodIdTable: called MethodIdTable\n"); fflush(stdout);
    printf("typeIdTable: calling fieldIdTable\n"); fflush(stdout);
    fieldIdTable(dex, dexLog, string_index, dataInMemory.strings);
    printf("typeIdTable: calling classDefTable\n"); fflush(stdout);
    classDefTable(dex, dexLog, string_index, dataInMemory.strings);
 
    cleanup:
        /*free(string_index);
        for(uint32_t a = 0; a < string_size; a++){
            if (string_data_array[a])free(string_data_array[a]);
        }
        free(string_data_array);*/
        fclose(file);
}

void methodIdTable(char *dex, FILE*dexLog, uint32_t *type_index, char **string_data_array){

    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        fclose(dexLog);
        return;
    }

    uint32_t method_ids_off, method_ids_size;

    fseek(file, 0x58, SEEK_SET);
    fread(&method_ids_size, 4, 1, file);

    fseek(file, 0x5C, SEEK_SET);
    fread(&method_ids_off, 4, 1, file);

    fseek(file, method_ids_off, SEEK_SET);
    uint16_t *class_idx, *proto_idx;
    uint32_t *name_idx;

    class_idx = malloc(sizeof(uint16_t) * method_ids_size);
    proto_idx = malloc(sizeof(uint16_t) * method_ids_size);
    name_idx = malloc(sizeof(uint32_t) * method_ids_size);
    if(class_idx == NULL || proto_idx  == NULL || name_idx== NULL){
        perror("Error allocating memory for method ids sizes\n");
        goto cleanup;
    }

    for(uint32_t i = 0; i < method_ids_size; i++){
        fread(&class_idx[i], sizeof(uint16_t), 1, file);
        fread(&proto_idx[i], sizeof(uint16_t), 1, file);
        fread(&name_idx[i], sizeof(uint32_t), 1, file);
    }
    /*uint32_t *method_idx;
    method_idx = malloc(sizeof(uint32_t) * method_ids_size);
    if(method_idx == NULL){
        perror("Error allocating memory for method ids sizes\n");
        goto cleanup;
    }*/
    uint32_t *type_idx_val;
    type_idx_val = malloc(sizeof(uint32_t)*method_ids_size);

    dataInMemory.method_definitions = malloc(method_ids_size * sizeof(char*));
    dataInMemory.method_definitions_count = method_ids_size;
    dataInMemory.method_class = malloc(method_ids_size * sizeof(char*));
    dataInMemory.method_class_count = method_ids_size;

    for (uint32_t a = 0; a < method_ids_size; a++) {
        
        type_idx_val[a] = type_index[class_idx[a]];
        //printf("hello, I am in methoid\n");
        dataInMemory.method_definitions[a] = string_data_array[name_idx[a]];
        //printf("hello, I am in methoid2\n");
        //printf("%s\n", dataInMemory.method_definitions[a]);
        dataInMemory.method_class[a] = string_data_array[type_idx_val[a]];
        //printf("%s\n", dataInMemory.method_definitions[a]);
        fprintf(dexLog, "[METHOD] name:%s ", dataInMemory.method_definitions[a]);
        fprintf(dexLog, "class:%s\n", dataInMemory.method_class[a]);
    }

    cleanup:
        //free(class_idx);
        //free(name_idx);
        free(proto_idx);
        //free(method_idx);
        fclose(file);
}

void fieldIdTable(char *dex, FILE*dexLog,uint32_t *type_string_index, char **string_data_array){
    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        fclose(dexLog);
        return;
    }
    //0x50 - size and 0x54 - off
    uint32_t field_ids_size, field_ids_off;

    // read the field size
    fseek(file, 0x50, SEEK_SET);
    fread(&field_ids_size, 4, 1, file);

    // get file offset location
    fseek(file, 0x54, SEEK_SET);
    fread(&field_ids_off, 4, 1, file);

    fseek(file, field_ids_off, SEEK_SET);
    uint16_t *class_idx, *type_idx;
    uint32_t *name_idx;

    class_idx = malloc(sizeof(uint16_t) * field_ids_size);
    type_idx = malloc(sizeof(uint16_t) * field_ids_size);
    name_idx = malloc(sizeof(uint32_t) * field_ids_size);
    if(class_idx == NULL || type_idx  == NULL || name_idx == NULL){
        perror("Error allocating memory for field ids sizes\n");
        goto cleanup;
    }
    for(uint32_t i = 0; i < field_ids_size; i++){
        fread(&class_idx[i], sizeof(uint16_t), 1, file);
        fread(&type_idx[i], sizeof(uint16_t), 1, file);
        fread(&name_idx[i], sizeof(uint32_t), 1, file);
    }
    uint32_t *class_index, *type_index;
    class_index = malloc(sizeof(uint32_t) * field_ids_size);
    type_index = malloc(sizeof(uint32_t) * field_ids_size);

    if (class_index == NULL || type_index == NULL){
        perror("Error allocating memory for field ids sizes\n");
        goto cleanup;
    }
    for(uint32_t j = 0; j < field_ids_size; j++){
        fprintf(dexLog, "[FIELD] name: %s, ", string_data_array[name_idx[j]]);
        class_index[j] = type_string_index[class_idx[j]];
        type_index[j] = type_string_index[type_idx[j]];
        fprintf(dexLog, "class:%s, ", string_data_array[class_index[j]]);
        fprintf(dexLog, "type:%s\n", string_data_array[type_index[j]]);
    }

    cleanup:
        free(class_idx);
        free(type_idx);
        free(name_idx);
        free(class_index);
        free(type_index);
        fclose(file);
}
void classDefTable(char *dex, FILE*dexLog,uint32_t *class_index, char **string_data_array){
    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        fclose(dexLog);
        return;
    }

    uint32_t class_defs_off, class_defs_size;
    // class offset 60 and class size 64
    fseek(file, 0x60, SEEK_SET);
    fread(&class_defs_size, 4, 1, file);

    fseek(file, 0x64, SEEK_SET);
    fread(&class_defs_off, 4, 1, file);

    fseek(file, class_defs_off, SEEK_SET);
    uint32_t *class_idx, *access_flags, *class_data_off, *superclass_idx;
    class_idx = malloc(sizeof(uint32_t) * class_defs_size);
    access_flags = malloc(sizeof(uint32_t) * class_defs_size);
    class_data_off = malloc(sizeof(uint32_t) * class_defs_size);
    superclass_idx = malloc(sizeof(uint32_t) * class_defs_size);

    if(class_idx == NULL || access_flags == NULL || class_data_off == NULL || superclass_idx == NULL ){
        perror("Error allocating memory for class defs sizes\n");
        goto cleanup;
    }

    for(uint32_t i = 0; i < class_defs_size; i++){
        // Read the fields of the class_def_item directly.
        fread(&class_idx[i], sizeof(uint32_t), 1, file);
        fread(&access_flags[i], sizeof(uint32_t), 1, file);
        fread(&superclass_idx[i], sizeof(uint32_t), 1, file);
        fseek(file, 12, SEEK_CUR); // Skip interfaces_off, source_file_idx, annotations_off
        fread(&class_data_off[i], sizeof(uint32_t), 1, file);
        fseek(file, 4, SEEK_CUR); // Skip static_values_off
    }
    
    dataInMemory.class_definitions = malloc(class_defs_size * sizeof(char*));
    dataInMemory.class_definitions_count = class_defs_size;
    dataInMemory.super_idx = malloc(class_defs_size * sizeof(char*));
    dataInMemory.super_idx_count = class_defs_size;

    uint32_t *c_index;
    c_index = malloc(sizeof(uint32_t)*class_defs_size);
    if(c_index == NULL){
        perror("Error allocating memory for class def size\n");
        goto cleanup;
    }
    for(uint32_t j = 0; j < class_defs_size; j++){
        c_index[j] = class_index[class_idx[j]];

        dataInMemory.class_definitions[j] = dataInMemory.strings[c_index[j]];
        dataInMemory.super_idx[j] = dataInMemory.strings[superclass_idx[j]];

        fprintf(dexLog, "[CLASS] name: %s, ", dataInMemory.class_definitions[j]);
        fprintf(dexLog, "flags: %u, \n", access_flags[j]);
    }
    printf("Calling class data items\n");
    class_data_item(dex, dexLog, class_data_off, class_defs_size);

    cleanup:
        free(superclass_idx);
        free(access_flags);
        free(class_data_off);
        fclose(file);
}
// typedef struct resolvedMethod{
//     uint32_t methodIdx;
//     uint32_t accessFlags;
//     uint32_t code_off;
// }*method;

// Helper to process a single code item
void process_code_item(FILE *file, FILE *dexLog, uint32_t code_off, uint32_t method_idx) {
    if (code_off == 0) return;
    
    long current_pos = ftell(file);
    fseek(file, code_off, SEEK_SET);

    uint16_t registers_size, ins_size, outs_size, tries_size;
    uint32_t debug_info_off, insns_size;

    fread(&registers_size, sizeof(uint16_t), 1, file);
    fread(&ins_size, sizeof(uint16_t), 1, file);
    fread(&outs_size, sizeof(uint16_t), 1, file);
    fread(&tries_size, sizeof(uint16_t), 1, file);
    fread(&debug_info_off, sizeof(uint32_t), 1, file);
    fread(&insns_size, sizeof(uint32_t), 1, file);

    // fprintf(dexLog, "[CODE] MethodIdx=%u, Regs=%u, Ins=%u, Outs=%u, InsnsSize=%u\n", 
    //        method_idx, registers_size, ins_size, outs_size, insns_size);
    
    // Here you could read the bytecode if needed
    // fseek(file, code_off + 16, SEEK_SET); // Instructions start after 16 byte header

    fseek(file, current_pos, SEEK_SET); // Restore position
}

void class_data_item(char *dex, FILE*dexLog, uint32_t *class_data_off, uint32_t class_defs_size){
    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        fclose(dexLog);
        return;
    }

    for(uint32_t i = 0; i < class_defs_size; i++){
        if (class_data_off[i] == 0) continue;

        fseek(file, class_data_off[i], SEEK_SET);

        uint32_t static_fields_size = readULEB128(file);
        uint32_t instance_fields_size = readULEB128(file);
        uint32_t direct_methods_size = readULEB128(file);
        uint32_t virtual_methods_size = readULEB128(file);

        // Skip fields
        for (uint32_t j = 0; j < static_fields_size; j++) {
            readULEB128(file); // field_idx_diff
            readULEB128(file); // access_flags
        }
        for (uint32_t j = 0; j < instance_fields_size; j++) {
            readULEB128(file); // field_idx_diff
            readULEB128(file); // access_flags
        }

        // Process Direct Methods
        uint32_t method_idx = 0;
        for (uint32_t j = 0; j < direct_methods_size; j++) {
            uint32_t diff = readULEB128(file);
            method_idx += diff;
            uint32_t access_flags = readULEB128(file);
            uint32_t code_off = readULEB128(file);
            
            if (code_off != 0) {
                 process_code_item(file, dexLog, code_off, method_idx);
            }
        }

        // Process Virtual Methods
        method_idx = 0;
        for (uint32_t j = 0; j < virtual_methods_size; j++) {
            uint32_t diff = readULEB128(file);
            method_idx += diff;
            uint32_t access_flags = readULEB128(file);
            uint32_t code_off = readULEB128(file);
            
            if (code_off != 0) {
                 process_code_item(file, dexLog, code_off, method_idx);
            }
        }
    }
    
    fclose(file);
}

void code_item(char *dex, FILE *dexLog, method direct , method virtual, uint32_t size){ 
    // Legacy function kept for signature compatibility if needed, 
    // but functionality moved to process_code_item and class_data_item.
    // The previous implementation was flawed (batch processing with incorrect sizes).
}

int logdex(char *dex){
    printf("logdex: called\n"); fflush(stdout);
    FILE *dexLog = fopen("dexLog_" __TIME__"_" __DATE__".txt", "a+");
    if(dexLog == NULL){
        perror("logdex: fopen");
        return EXIT_FAILURE;
    }
    printf("logdex: opened log file\n"); fflush(stdout);

    printf("logdex: calling dexheaderScan\n"); fflush(stdout);
    dexheaderScan(dex, dexLog);
    printf("logdex: calling dexstringData\n"); fflush(stdout);
    dexstringData(dex, dexLog);
    printf("logdex: calling typeIdTable\n"); fflush(stdout);
    typeIdTable(dex, dexLog);
    printf("logdex: finished all calls\n"); fflush(stdout);

    fclose(dexLog);
    return(EXIT_SUCCESS);
}

void freeKeepMemory(keepMemory mem){
    if (mem.strings) {
        // for(uint32_t i = 0; i < mem.strings_count; i++){
        //     //free(mem.strings[i]);
        // }
        free(mem.strings);
    }
    if (mem.method_definitions) {
        // for(uint32_t i = 0; i < mem.method_definitions_count; i++){
        //     //free(mem.method_definitions[i]);
        // }
        free(mem.method_definitions);
    }
    if (mem.method_class) {
        // for(uint32_t i = 0; i < mem.method_class_count; i++){
        //     //free(mem.method_class[i]);
        // }
        free(mem.method_class);
    }
    if (mem.class_definitions) {
        // for(uint32_t i = 0; i < mem.class_definitions_count; i++){
        //     //free(mem.class_definitions[i]);
        // }
        free(mem.class_definitions);
    }
    if (mem.super_idx) {
        // for(uint32_t i = 0; i < mem.super_idx_count; i++){
        //     //free(mem.super_idx[i]);
        // }
        free(mem.super_idx);
    }
    
}