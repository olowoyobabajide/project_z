#include "main.h"

typedef struct {
    char **hash;
}MD5;
typedef struct {
    char **hash;
}SHA1;
typedef struct {
    char **hash;
}SHA256;
MD5 md5hash;
SHA1 sha1hash;
SHA256 sha256hash;

size_t NUM_MD5 = sizeof(md5hash)/sizeof(MD5);
size_t NUM_SHA1 = sizeof(sha1hash)/sizeof(SHA1);
size_t NUM_SHA256 = sizeof(sha256hash)/sizeof(SHA256);

void threat_hash(char *file){
    FILE *threat_DB;

    if((threat_DB = fopen(file, "r")) == NULL){
        perror("Unable to read threat Database");
        fclose(threat_DB);
    }
    // md5: 986
    // sha1: 905
    // sha256: 1174
    md5hash.hash = malloc(sizeof(char*)*986);
    sha1hash.hash = malloc(sizeof(char*)*905);
    sha256hash.hash = malloc(sizeof(char*)*1174);
    if (md5hash.hash == NULL || sha1hash.hash == NULL || sha256hash.hash == NULL) {
    perror("Failed to allocate memory for hash pointers");}
    char s[100];
    int i = 0, j = 0, k = 0;
    while(fgets(s, sizeof s, threat_DB) != NULL){
        s[strcspn(s, "\r\n")] = '\0';
        if(strlen(s) == 32){
            printf("yes32\n");
            md5hash.hash[i] = strdup(s);
            i++;
        }
        if(strlen(s) == 40){
            printf("yes40\n");
            sha1hash.hash[j] = strdup(s);
            j++;
        }
        if(strlen(s) == 64){
            printf("yes64\n");
            sha256hash.hash[k] = strdup(s);
            k++;
        }
    }
    fclose(threat_DB);
}

void hash_sum(char *so_file){
    FILE *p_hash;

    char md5sum[40], sha1sum[40], sha256sum[40];
    snprintf(md5sum, 40, "md5sum %s", so_file);
    snprintf(sha1sum, 40, "sha1sum %s", so_file);
    snprintf(sha256sum, 40, "sha256sum %s", so_file);

    threat_hash("Flagged_Hash_List.csv"); // stores the threat db hashes in memory temporarily
    char temp[65];
    if((p_hash = popen(md5sum, "r"))){
        if(fgets(temp, 65, p_hash)){
            strtok(temp, " ");
            for(int i = 0; i < NUM_MD5; i++){
                if(strcmp(temp, md5hash.hash[i]) == 0){
                    printf("%s\n", temp);
                    printf("VULNERABILTY FOUND! md5hash \n");
                    
                }
            }
            for(int i = 0; i < NUM_SHA1; i++){
                if(strcmp(temp, sha1hash.hash[i]) == 0){
                    printf("%s ", temp);
                    printf("VULNERABILTY FOUND! sha1hash\n");
                }
            }
            for(int i = 0; i < NUM_SHA256; i++){
                if(strcmp(temp, sha256hash.hash[i]) == 0){
                    printf("%s ", temp);
                    printf("VULNERABILTY FOUND! sha256hash \n");
                }
            }
            
        }
    }
    pclose(p_hash);
    
}


