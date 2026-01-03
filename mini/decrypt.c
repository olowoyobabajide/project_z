#include <stdio.h>
#include <stdlib.h>

void decrypt(FILE *encrypted_file, FILE *decrypted_file, FILE *key_file)
{
    int c, d;
    while ((c = fgetc(encrypted_file)) != EOF && (d = fgetc(key_file)) != EOF)
    {
        int decrypted_c = c ^ d;

        fputc(decrypted_c, decrypted_file);
    }
    
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Pls enter encrypted file");
    }
    else{
        
        char *encrypted = argv[1];
        char *key = argv[2];
        FILE *encrypted_file = fopen(encrypted, "r");
        FILE *decrypted_file = fopen("decrypt.out", "w");
        FILE *key_file = fopen(key, "r");

        decrypt(encrypted_file, decrypted_file, key_file);
     
        fclose(decrypted_file);
    }
}