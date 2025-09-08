#include <stdint.h>
#include "main.h"

/**
 * dex file scanning
 */

void dexPrint(char *str, uint32_t value, FILE *log);
void dexstringData(char *dex);
int binaryConvert(uint32_t num, uint32_t size);
uint32_t readULEB128(FILE *file);
char* readDexString(FILE *file);

struct DangerousString {
    const char *category;
    const char *string;
    const char *reason;
};

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
    dexheaderScan("classes.dex");
    dexstringData("classes.dex");

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
    fprintf(dexLog, "\n------\n\n");
    fclose(file);
    fclose(dexLog);
 }

void dexstringData(char *dex){
    
    FILE *file, *dexLog;

    if((dexLog = fopen("dexLog.txt", "a+")) == NULL){
        fprintf(stderr, "Can't create dex log file\n");
        fclose(dexLog);
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
        current_string_offset[i] = string_id_off;
    }
    for(uint32_t j = 1; j < string_size; j++){
        fseek(file, current_string_offset[j], SEEK_SET);
        char *str = readDexString(file);
        if(str){
            int a = 0;
            while (a < 30){
                if((strpbrk(watchlist[a].string, str)) != NULL){
                    dexPrint("String found!: %s\n", watchlist[a].string, dexLog);
                    dexPrint("Category: %s\n", watchlist[a].category, dexLog);
                    dexPrint("Reason: %s\n", watchlist[a].reason, dexLog);
                }
                a++;
            }
            free(str);
        }
    }
    fclose(dexLog);
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