#include "main.h"

// gcc -I. *.c src/*.c -o fs_analyzer $(pkg-config --cflags --libs libxml-2.0) 
int main(int argc, char **argv)
{
    static char buffer[PATH_MAX];
    if(argc < 2)
    {
        printf("Insufficient or too much input\n");
        printf("Try './main /path/to/folder/\n'");
        return EXIT_FAILURE;
    }
    sscanf(argv[1], "%255s", &buffer);
    printf("Calling apk_check with path: %s\n", buffer);
    apk_check(buffer);

    printf("Calling filecheckManifest with path: %s\n", buffer);
    filecheckManifest(buffer); // For Android Manifest
    printf("Calling filecheckDex with path: %s\n", buffer);
    filecheckDex(buffer); // For .dex files 
    printf("Calling filecheckso with path: %s\n", buffer);
    filecheckso(buffer); // For shared object files
    filecheckAll("/home/jyde/Documents/project_z/code/temp"); // for checking all files
    // printf("%s\n", base_path);
    
    /*if(strstr("-o", argv[i])){
        printf("happened\n");
        snprintf(base_path, PATH_MAX, "%255s", argv[i+1]);
    }*/
    

}