#include "main.h"

int main(int argc, char **argv)
{
    static char buffer[PATH_MAX];

    if(argc != 2)
    {
        printf("Insufficient or too much input\n");
        printf("Try './main /path/to/folder\n'");
        return EXIT_FAILURE;
    }
    sscanf(argv[1], "%255s", &buffer);
    apk_check(buffer);

    analyse_per(buffer); // For Android Manifest
    filecheckDex(buffer); // For DEX
}