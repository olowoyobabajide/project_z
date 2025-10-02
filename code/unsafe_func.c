#include "main.h"

keepMemory dataSafe;
typedef struct unsafe{
    char *unsafe_func;
} unsafeFunctions;

unsafeFunctions functions[] = {
    "strcpy", "gets", "strcat", "system", "peopen"
};

void unsafeFunc(char *dex){
    FILE *dex_file;
    if((dex_file = fopen(dex, "rb")) == NULL){
        fprintf(stderr, "Unable to read *.dex file\n");
        return;   
    }
    
    for(uint32_t i = 0; i < dataSafe.strings_count; i++){
        for(int j = 0; j < 5; j++){
            if(strstr(dataSafe.strings[j], functions[j].unsafe_func)){
                printf("WARNING: %s found. Pls check use case\n", functions[j].unsafe_func);
            }
        }
    }
}