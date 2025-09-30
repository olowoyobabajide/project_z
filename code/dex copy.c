#include <stdint.h>
#include "main.h"

/**
 * dex file scanning
 */

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
int logdex();
struct DangerousString {
    const char *category;
    const char *string;
    const char *reason;
};
keepMemory dataInMemory;

struct DangerousString watchlist[55] = {
    // --- Privilege Escalation / Rooting ---
    {"Privilege Escalation", "su", "Potential root command or binary"},
    {"Privilege Escalation", "root", "May indicate root detection or privilege escalation"},
    {"Privilege Escala tion", "busybox", "Busybox often bundled with rooting tools"},
    {"Privilege Escalation", "magisk", "Magisk root manager detection"},
    {"Privilege Escalation", "supersu", "SuperSU root manager detection"},
    {"Privilege Escalation", "setuid", "Setting user ID, privilege abuse"},
    {"Privilege Escalation", "chmod", "Altering file permissions"},
    {"Privilege Escalation", "chown", "Changing file ownership"},
    {"Privilege Escalation", "mount", "Mounting file systems, potential rootkit"},
    {"Privilege Escalation", "sh", "Direct shell execution"},

    // --- Sensitive File Paths ---
    {"Sensitive File", "/system/bin/sh", "Direct shell execution path"},
    {"Sensitive File", "/system/xbin/su", "su binary location"},
    {"Sensitive File", "/data/local/tmp", "Temporary storage, malware often hides payloads here"},
    {"Sensitive File", "/proc/", "Accessing process info, potential data leak"},
    {"Sensitive File", "/etc/passwd", "Unix password file"},
    {"Sensitive File", "/etc/shadow", "Unix shadow passwords"},

    // --- Dangerous Android Permissions ---
    {"Dangerous Permission", "android.permission.SEND_SMS", "May send SMS without user knowledge"},
    {"Dangerous Permission", "android.permission.RECEIVE_SMS", "May intercept SMS"},
    {"Dangerous Permission", "android.permission.CALL_PHONE", "May place calls without consent"},
    {"Dangerous Permission", "android.permission.READ_SMS", "Reads SMS content"},
    {"Dangerous Permission", "android.permission.WRITE_SMS", "Modifies SMS database"},
    {"Dangerous Permission", "android.permission.RECORD_AUDIO", "Can spy on microphone"},
    {"Dangerous Permission", "android.permission.CAMERA", "Can spy on camera"},
    {"Dangerous Permission", "android.permission.WRITE_SETTINGS", "Modifies device settings"},
    {"Dangerous Permission", "android.permission.SYSTEM_ALERT_WINDOW", "Overlay attacks / phishing windows"},

    // --- Network Abuse / C2 Communication ---
    {"Network Abuse", "http://", "Unencrypted connection, potential C2 traffic"},
    {"Network Abuse", "https://", "Encrypted connection, check for hardcoded domains"},
    {"Network Abuse", "ftp://", "FTP connection, unusual for apps"},
    {"Network Abuse", "socket://", "Direct socket communication"},
    {"Network Abuse", "127.0.0.1", "Localhost binding, backdoor possibility"},
    {"Network Abuse", "192.168.", "Private network IP, suspicious hardcoding"},
    {"Network Abuse", "10.", "Private network IP, suspicious hardcoding"},
    {"Network Abuse", "172.", "Private network IP, suspicious hardcoding"},
    {"Network Abuse", ".ru", "Russian domain, often linked with C2"},
    {"Network Abuse", ".cn", "Chinese domain, often linked with C2"},
    {"Network Abuse", ".biz", "Suspicious TLD, often abused"},

    // --- Data Exfiltration / Credential Theft ---
    {"Data Exfiltration", "getDeviceId", "Accessing unique device identifier"},
    {"Data Exfiltration", "android_id", "Tracking device with Android ID"},
    {"Data Exfiltration", "telephony", "Accessing telephony services"},
    {"Data Exfiltration", "accounts", "May steal account info"},
    {"Data Exfiltration", "IMEI", "Grabbing device IMEI"},
    {"Data Exfiltration", "ICCID", "Grabbing SIM ICCID"},
    {"Data Exfiltration", "location", "Tracking user location"},
    {"Data Exfiltration", "keystore", "Targeting secure storage"},
    {"Data Exfiltration", "password", "Hardcoded password handling"},
    {"Data Exfiltration", "token", "API or session token"},
    {"Data Exfiltration", "encryptionKey", "Hardcoded encryption keys"},

    // --- Obfuscation / Malware Tricks ---
    {"Obfuscation", "Base64", "Often used to hide payloads"},
    {"Obfuscation", "AES", "Encryption reference, check for misuse"},
    {"Obfuscation", "DES", "Weak encryption reference"},
    {"Obfuscation", "xor", "Obfuscation with XOR"},
    {"Obfuscation", "payload", "Malware payload reference"},
    {"Obfuscation", "decode", "Decoding routines, hiding data"},
    {"Obfuscation", "dexclassloader", "Dynamic code loading"},
    {"Obfuscation", "loadLibrary", "Loading external native code"}
};

int main()
{

    logdex();
    /*if (fork() == 0){
        analyseDex(dataInMemory.strings, dataInMemory.type_descriptors, dataInMemory.class_definitions, dataInMemory.method_definitions, dataInMemory.method_class, dataInMemory.super_idx);
        exit(0);
    }
    else{
        //dexheaderScan("classes.dex");
        //dexstringData("classes.dex");
        logdex();
        printf("done\n");
        wait(0);
    }*/
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
    
    FILE *file;

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
        current_string_offset[i] = string_id_off;
    }

    /*dataInMemory.strings = malloc(sizeof(char*) * string_size);
    if(dataInMemory.strings == NULL){
        perror("Error allocating memory for string size\n");
        goto cleanup;
    }*/
    for(uint32_t j = 0; j < string_size; j++){
        fseek(file, current_string_offset[j], SEEK_SET);
        char *str = readDexString(file);
        if(str){
            //dataInMemory.strings[j] = str;
            fprintf(dexLog, "%s\n", str);
            /*if((strstr(str, watchlist[a].string)) != NULL){
                fprintf(dexLog, "[dexHeader] String found!:%s, Category:%s, Reason:%s\n", watchlist[a]. string, watchlist[a].category, watchlist[a].reason);
            }*/
            }
            free(str);
    }

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
    free(current_string_offset); // Free the offset array now that we're done with it
    
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
    /*dataInMemory.type_descriptors = malloc(sizeof(char*) * type_ids_size);
    if(dataInMemory.type_descriptors == NULL){
        perror("Error allocating memory for string size\n");
        goto cleanup;
    }*/
    for(uint32_t i = 0; i < type_ids_size; i++){
        uint32_t offset;
        fread(&offset, 4, 1, file);
        string_index[i] = offset;
        //dataInMemory.type_descriptors[i] = string_data_array[string_index[i]];
        //printf("%s\n", dataInMemory.type_descriptors[i]);
        fprintf(dexLog, "[TYPE] index=%d, decriptor=%s\n", string_index[i], string_data_array[string_index[i]]);
    }
    methodIdTable("classes.dex", dexLog, string_index, string_data_array);
    fieldIdTable("classes.dex", dexLog, string_index, string_data_array);
    classDefTable("classes.dex", dexLog, string_index, string_data_array);
 
    cleanup:
        free(string_index);
        for(uint32_t a = 0; a < string_size; a++){
            if (string_data_array[a])free(string_data_array[a]);
        }
        free(string_data_array);
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
    uint32_t *method_idx;
    method_idx = malloc(sizeof(uint32_t) * method_ids_size);
    if(method_idx == NULL){
        perror("Error allocating memory for method ids sizes\n");
        goto cleanup;
    }

    /*dataInMemory.method_definitions = malloc(sizeof(char*) * method_ids_size);
    dataInMemory.method_class = malloc(sizeof(char*) * method_ids_size);

    if(dataInMemory.method_definitions == NULL || dataInMemory.method_class == NULL){
        perror("Error allocating memory for method_ids_size\n");
        goto cleanup;
    }*/
    for (uint32_t a = 0; a < method_ids_size; a++){
        method_idx[a] = type_index[class_idx[a]];
        //dataInMemory.method_definitions[a] = string_data_array[name_idx[a]];
        //dataInMemory.method_class[a] = string_data_array[method_idx[a]];
        fprintf(dexLog, "[METHOD] name:%s ", string_data_array[name_idx[a]]);
        fprintf(dexLog, "class:%s\n", string_data_array[method_idx[a]]);
    }

    cleanup:
        free(class_idx);
        free(name_idx);
        free(proto_idx);
        free(method_idx);
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
    uint32_t *class_idx, *access_flags, *class_data_off;
    class_idx = malloc(sizeof(uint32_t) * class_defs_size);
    access_flags = malloc(sizeof(uint32_t) * class_defs_size);
    class_data_off = malloc(sizeof(uint32_t) * class_defs_size);
    if(class_idx == NULL || access_flags == NULL || class_data_off == NULL){
        perror("Error allocating memory for class defs sizes\n");
        goto cleanup;
    }

    for(uint32_t i = 0; i < class_defs_size; i++){
        // Read the fields of the class_def_item directly.
        fread(&class_idx[i], sizeof(uint32_t), 1, file);
        fread(&access_flags[i], sizeof(uint32_t), 1, file);
        fseek(file, 16, SEEK_CUR); // Skip superclass_idx, interfaces_off, source_file_idx, annotations_off
        fread(&class_data_off[i], sizeof(uint32_t), 1, file);
        fseek(file, 4, SEEK_CUR); // Skip static_values_off
    }
    uint32_t *c_index;
    c_index = malloc(sizeof(uint32_t)*class_defs_size);
    if(c_index == NULL){
        perror("Error allocating memory for class def size\n");
        goto cleanup;
    }
    for(uint32_t j = 0; j < class_defs_size; j++){
        c_index[j] = class_index[class_idx[j]];
        fprintf(dexLog, "[CLASS] name: %s, ", string_data_array[c_index[j]]);
        fprintf(dexLog, "flags: %u, \n", access_flags[j]);
    }
    class_data_item("classes.dex", dexLog, class_data_off, class_defs_size);

    cleanup:
        free(c_index);
        free(class_idx);
        free(access_flags);
        free(class_data_off);
        fclose(file);
}

void class_data_item(char *dex, FILE*dexLog, uint32_t *class_data_off, uint32_t class_defs_size){
    FILE *file;

    if((file = fopen(dex, "rb"))== NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        fclose(dexLog);
        return;
    }
    uint32_t *static_fields_size = NULL;
    uint32_t *instance_fields_size = NULL;
    uint32_t *direct_methods_size = NULL;
    uint32_t *virtual_methods_size = NULL;

    static_fields_size = malloc(sizeof(uint32_t)*class_defs_size);
    instance_fields_size = malloc(sizeof(uint32_t)*class_defs_size);
    direct_methods_size = malloc(sizeof(uint32_t)*class_defs_size);
    virtual_methods_size = malloc(sizeof(uint32_t)*class_defs_size);
    if (!static_fields_size || !instance_fields_size || !direct_methods_size || !virtual_methods_size) {
        perror("Error allocating memory for class data sizes\n");
        goto cleanup; // Use goto for centralized cleanup
    }

    for(uint32_t i = 0; i < class_defs_size; i++){
        if (class_data_off[i] != 0) {
            fseek(file, class_data_off[i], SEEK_SET);

            static_fields_size[i] = readULEB128(file);
            instance_fields_size[i] = readULEB128(file);
            direct_methods_size[i] = readULEB128(file);
            virtual_methods_size[i] = readULEB128(file);
        } else {
            // No class data for this item, set sizes to 0
            static_fields_size[i] = 0;
            instance_fields_size[i] = 0;
            direct_methods_size[i] = 0;
            virtual_methods_size[i] = 0;
        }
    }
    for (uint32_t j = 0; j < class_defs_size; j++){
        fprintf(dexLog, "[CLASS_DATA] Item %d: static_fields=%u, instance_fields=%u, direct_methods=%u, virtual_methods=%u\n",
                j, static_fields_size[j], instance_fields_size[j], direct_methods_size[j], virtual_methods_size[j]);
    }

cleanup:
    free(static_fields_size);
    free(instance_fields_size);
    free(direct_methods_size);
    free(virtual_methods_size);
    fclose(file);
}

int logdex(){
    //This function handles logging
    FILE *dexLog;

    if((dexLog = fopen("testLog.txt", "w")) == NULL){
        fprintf(stderr, "Can't create dex log file\n");
        fclose(dexLog);
    }
    dexheaderScan("classes.dex", dexLog);
    dexstringData("classes.dex", dexLog);
    typeIdTable("classes.dex", dexLog);
    return(EXIT_SUCCESS);
}

void freeKeepMemory(){

}