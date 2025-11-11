#include "main.h"
#include <openssl/evp.h>
// #include <openssl/md5.h>
// #include <openssl/sha.h>

typedef struct {
    char **hash;
}threatMD5;
typedef struct {
    char **hash;
}threatSHA1;
typedef struct {
    char **hash;
}threatSHA256;

threatMD5 threatmd5;
threatSHA1 threatsha1;
threatSHA256 threatsha256;

size_t NUM_threatMD5 = sizeof(threatmd5)/sizeof(threatMD5);
size_t NUM_threatSHA1 = sizeof(threatsha1)/sizeof(threatSHA1);
size_t NUM_threatSHA256 = sizeof(threatsha256)/sizeof(threatSHA256);

void threat_hash(char *file);
void threat_hash(char *file){
    FILE *threat_DB;

    if((threat_DB = fopen(file, "r")) == NULL){
        perror("Unable to read threat Database");
        fclose(threat_DB);
    }
    // md5: 986
    // sha1: 905
    // sha256: 1174
    threatmd5.hash = malloc(sizeof(char*)*986);
    threatsha1.hash = malloc(sizeof(char*)*905);
    threatsha256.hash = malloc(sizeof(char*)*1174);
    if (threatmd5.hash == NULL || threatsha1.hash == NULL || threatsha256.hash == NULL) {
    perror("Failed to allocate memory for hash pointers");}
    char s[100];
    int i = 0, j = 0, k = 0;
    while(fgets(s, sizeof s, threat_DB) != NULL){
        s[strcspn(s, "\r\n")] = '\0';
        if(strlen(s) == 32){
            threatmd5.hash[i] = strdup(s);
            i++;
        }
        if(strlen(s) == 40){
            threatsha1.hash[j] = strdup(s);
            j++;
        }
        if(strlen(s) == 64){
            threatsha256.hash[k] = strdup(s);
            k++;
        }
    }
    fclose(threat_DB);
}

void verifyHash(char *file){
    FILE *doc;

    if((doc = fopen(file, "r")) == NULL){
        perror("Unable to read file for hash check");
        return;
    }

    threat_hash("Flagged_Hash_List.csv");
    uint64_t FILE_SIZE;
    fseek(doc, 0, SEEK_END);
    FILE_SIZE = ftell(doc);

    printf("File size: %d\n", FILE_SIZE);

    char file_content[FILE_SIZE];

    fseek(doc, 0, SEEK_SET);
    fread(file_content, FILE_SIZE, 1, doc);

    unsigned char *md5_hash;
    unsigned char *sha1_hash;
    unsigned char *sha256_hash;

    unsigned int digest_length;
    EVP_MD_CTX *hash_ctx;

    if((hash_ctx = EVP_MD_CTX_new()) == NULL){perror("Error allocating size for hash");}
    if(1 != EVP_DigestInit_ex(hash_ctx, EVP_md5(), NULL)){perror("Error allocating size for hash");}
    if(1 != EVP_DigestUpdate(hash_ctx, file_content, FILE_SIZE)){perror("Error allocating size for hash");}
    // if((*md5_hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL){
    //     {perror("Error allocating size for hash");}
    // }
    if(1 != EVP_DigestFinal_ex(hash_ctx, md5_hash, &digest_length)){perror("Error allocating size for hash");}
    //printf("%s\n", *md5_hash);
    //printf("SHA256 Hash of \"%s\": ", file_conte);
    for (unsigned int i = 0; i < digest_length; i++) {
        printf("%02x", md5_hash[i]);
    }
    printf("\n");

    /*MD5((unsigned char*)file_content, FILE_SIZE, md5_hash);
    /*SHA1((unsigned char*)file_content, FILE_SIZE, sha1_hash);
    SHA256((unsigned char*)file_content, FILE_SIZE, sha256_hash);


    for(int md5_count = 0; md5_count < NUM_threatMD5; md5_count++){
        if(strstr(md5_hash, threatmd5.hash[md5_count])){
            printf("%s\n", md5_hash);
            printf("VULNERABILTY FOUND! md5hash \n");
        }
    }
    for(int sha_count = 0; sha_count < NUM_threatSHA1; sha_count++){
        if(strstr(sha1_hash, threatsha1.hash[sha_count])){
            printf("%s\n", sha1_hash);
            printf("VULNERABILTY FOUND! sha1hash\n");
        }
    }
    for(int sha_count = 0; sha_count < NUM_threatSHA256; sha_count++){
        if(strstr(sha256_hash, threatsha256.hash[sha_count])){
            printf("%s\n", sha256_hash);
            printf("VULNERABILTY FOUND! sha1hash\n");
        }
    }*/


    // char temp[65];
    // if((p_hash = popen(md5sum, "r"))){
    //     if(fgets(temp, 65, p_hash)){
    //         strtok(temp, " ");
    //         for(int i = 0; i < NUM_MD5; i++){
    //             if(strcmp(temp, md5hash.hash[i]) == 0){
    //                 printf("%s\n", temp);
    //                 printf("VULNERABILTY FOUND! md5hash \n");
                    
    //             }
    //         }
    //         for(int i = 0; i < NUM_SHA1; i++){
    //             if(strcmp(temp, sha1hash.hash[i]) == 0){
    //                 printf("%s ", temp);
    //                 printf("VULNERABILTY FOUND! sha1hash\n");
    //             }
    //         }
    //         for(int i = 0; i < NUM_SHA256; i++){
    //             if(strcmp(temp, sha256hash.hash[i]) == 0){
    //                 printf("%s ", temp);
    //                 printf("VULNERABILTY FOUND! sha256hash \n");
    //             }
    //         }
            
    //     }
    // }
    // pclose(p_hash);
    EVP_MD_CTX_free(hash_ctx);
    //fclose(doc);
}
