#include "main.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

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

// Global counters for actual number of loaded hashes
size_t count_md5 = 0;
size_t count_sha1 = 0;
size_t count_sha256 = 0;
int db_loaded = 0;

void threat_hash(char *file);
void threat_hash(char *file){
    if (db_loaded) return; // Prevent re-loading and memory leaks

    FILE *threat_DB;

    if((threat_DB = fopen(file, "r")) == NULL){
        // perror("Unable to read threat Database"); // Optional: warn if missing
        return;
    }
    // md5: 986
    // sha1: 905
    // sha256: 1174
    threatmd5.hash = malloc(sizeof(char*)*986);
    threatsha1.hash = malloc(sizeof(char*)*905);
    threatsha256.hash = malloc(sizeof(char*)*1174);
    
    if (threatmd5.hash == NULL || threatsha1.hash == NULL || threatsha256.hash == NULL) {
        perror("Failed to allocate memory for hash pointers");
        fclose(threat_DB);
        return;
    }

    char s[100];
    // i, j, k already correspond to our global counters
    count_md5 = 0; count_sha1 = 0; count_sha256 = 0;

    while(fgets(s, sizeof s, threat_DB) != NULL){
        s[strcspn(s, "\r\n")] = '\0';
        if(strlen(s) == 32){
            if (count_md5 < 986) threatmd5.hash[count_md5++] = strdup(s);
        }
        if(strlen(s) == 40){
            if (count_sha1 < 905) threatsha1.hash[count_sha1++] = strdup(s);
        }
        if(strlen(s) == 64){
            if (count_sha256 < 1174) threatsha256.hash[count_sha256++] = strdup(s);
        }
    }
    fclose(threat_DB);
    db_loaded = 1;
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

    char *file_content = malloc(FILE_SIZE);
    rewind(doc);
    fread(file_content, FILE_SIZE, 1, doc);

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

    unsigned int digest_length = 0;;
    EVP_MD_CTX *hash_ctx;
    EVP_MD_CTX *sha1_ctx;
    EVP_MD_CTX *sha256_ctx;

    // md5 hashing
    if((hash_ctx = EVP_MD_CTX_new()) == NULL){perror("md5:EVP_MD_CTX_new");}
    if(1 != EVP_DigestInit_ex(hash_ctx, EVP_md5(), NULL)){perror("md5:EVP_DigestInit_ex");}
    if(1 != EVP_DigestUpdate(hash_ctx, file_content, FILE_SIZE)){perror("md5:EVP_DigestUpdate");}
    if(1 != EVP_DigestFinal_ex(hash_ctx, md5_hash, &digest_length)){perror("md5:EVP_DigestFinal_ex");}

    char md5_string[33];
    for (unsigned int i = 0; i < digest_length; i++) {
        //printf("%02x", md5_hash[i]);
        sprintf(&md5_string[i*2], "%02x", md5_hash[i]);
    }
    md5_string[32] = '\0';

    for(uint32_t md5_count = 0; md5_count < count_md5; md5_count++){
        if(strcmp(md5_string, threatmd5.hash[md5_count]) == 0){
            printf("%s\n", md5_string);
            printf("VULNERABILTY FOUND! md5hash\n");
        }
    }

    // sha1 hashing
    if((sha1_ctx = EVP_MD_CTX_new()) == NULL){perror("sha1:EVP_MD_CTX_new");}
    if(1 != EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL)){perror("sha1:EVP_DigestInit_ex");}
    if(1 != EVP_DigestUpdate(sha1_ctx, file_content, FILE_SIZE)){perror("sha1:EVP_DigestUpdate");}
    if(1 != EVP_DigestFinal_ex(sha1_ctx, sha1_hash, &digest_length)){perror("sha1:EVP_DigestFinal_ex");}
    
    char sha1_string[41];
    for (unsigned int i = 0; i < digest_length; i++) {
        //printf("%02x", sha1_hash[i]);
        sprintf(&sha1_string[i*2], "%02x", sha1_hash[i]);
    }
    sha1_string[40] = '\0';

    for(int sha_count = 0; sha_count < count_sha1; sha_count++){
        if(strcmp(sha1_string, threatsha1.hash[sha_count]) == 0){
            printf("%s\n", sha1_string);
            printf("VULNERABILTY FOUND! sha1hash\n");
        }
    }

    // sha256 hashing
    if((sha256_ctx = EVP_MD_CTX_new()) == NULL){perror("sha256:EVP_MD_CTX_new");}
    if(1 != EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL)){perror("sha256:EVP_DigestInit_ex");}
    if(1 != EVP_DigestUpdate(sha256_ctx, file_content, FILE_SIZE)){perror("sha256:EVP_DigestUpdate");}
    if(1 != EVP_DigestFinal_ex(sha256_ctx, sha256_hash, &digest_length)){perror("sha256:EVP_DigestFinal_ex");}

    char sha256_string[65]; // Fixed size
    for (unsigned int i = 0; i < digest_length; i++) {
        sprintf(&sha256_string[i*2], "%02x", sha256_hash[i]); // Fixed source array
    }
    sha256_string[64] = '\0';
    for(int sha_count = 0; sha_count < count_sha256; sha_count++){
        if(strcmp(sha256_string, threatsha256.hash[sha_count]) == 0){ // Fixed compare string
            printf("%s\n", sha256_string);
            printf("VULNERABILTY FOUND! sha256hash\n");
        }
    }

    free(file_content);
    EVP_MD_CTX_free(hash_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);
    
    fclose(doc);
}

